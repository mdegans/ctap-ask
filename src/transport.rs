//! CTAPHID (CTAP 2.1 §11.2): messages framed into 64-byte HID packets.
//!
//! Two CTAPHID commands are ever sent: INIT (channel allocation) and CBOR.
//! A CBOR message can only be built from a [`Request`], which has passed
//! the allow-list; this module refuses any CTAPHID command that is not
//! INIT or CBOR as a second line of defence.

use crate::allow::Request;
use crate::error::Error;
use rand_core::{OsRng, RngCore};
use std::time::{Duration, Instant};

pub(crate) const PACKET: usize = 64;
const BROADCAST_CID: [u8; 4] = [0xff; 4];
/// The largest CTAPHID message: 57 bytes in the initialization packet and
/// 59 in each of 128 continuation packets.
const MAX_MESSAGE: usize = (PACKET - 7) + 128 * (PACKET - 5);

const CMD_INIT: u8 = 0x06;
const CMD_CBOR: u8 = 0x10;
const CMD_KEEPALIVE: u8 = 0x3b;
const CMD_ERROR: u8 = 0x3f;

/// The CBOR capability bit in the INIT reply.
const CAPABILITY_CBOR: u8 = 0x04;

/// How long to wait for any one CBOR response, including the time a touch
/// takes. Keys time a touch out themselves (about 30 s) and answer with an
/// error, so this is a backstop, not the normal path.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(45);
/// How long to wait for the reply to INIT.
const INIT_TIMEOUT: Duration = Duration::from_secs(3);
/// One read's wait; the deadline is checked between reads.
const READ_SLICE: Duration = Duration::from_millis(250);

/// What a key says while it is still working on a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Keepalive {
    /// The key is processing.
    Processing,
    /// The key is waiting for a touch. Seeing this after asking for an
    /// assertion without user presence means the key wants a touch anyway.
    UserPresenceNeeded,
    /// A status this crate does not know.
    Other(u8),
}

impl From<u8> for Keepalive {
    fn from(status: u8) -> Self {
        match status {
            1 => Keepalive::Processing,
            2 => Keepalive::UserPresenceNeeded,
            other => Keepalive::Other(other),
        }
    }
}

/// What the key said about itself when the channel was opened
/// (CTAPHID_INIT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtaphidInit {
    /// The CTAPHID protocol version.
    pub protocol_version: u8,
    /// The device's own version: major, minor, build.
    pub device_version: (u8, u8, u8),
    /// The capability flags: `0x01` WINK, `0x04` CBOR, `0x08` NMSG.
    pub capabilities: u8,
}

/// Something that carries one checked CTAP request to an authenticator and
/// brings back the reply (status byte first). The CTAP layer above knows
/// nothing else about the transport.
pub(crate) trait CborTransport: Send {
    fn cbor(
        &mut self,
        request: &Request,
        on_keepalive: &mut dyn FnMut(Keepalive),
    ) -> Result<Vec<u8>, Error>;

    /// The CTAPHID_INIT reply, for a transport that has one.
    fn ctaphid_init(&self) -> Option<CtaphidInit> {
        None
    }
}

/// Something that moves 64-byte packets: a HID device, or a test.
pub(crate) trait PacketIo: Send {
    fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<(), Error>;
    /// One packet, or `None` if none arrived within `timeout`.
    fn read_packet(&mut self, timeout: Duration) -> Result<Option<[u8; PACKET]>, Error>;
}

/// A CTAPHID channel over some packet I/O.
pub(crate) struct Ctaphid<P> {
    io: P,
    cid: [u8; 4],
    init: CtaphidInit,
    response_timeout: Duration,
}

impl<P: PacketIo> Ctaphid<P> {
    /// Allocate a channel (CTAPHID_INIT) and check the key speaks CTAP2.
    pub(crate) fn open(io: P) -> Result<Self, Error> {
        Self::open_with_timeouts(io, INIT_TIMEOUT, RESPONSE_TIMEOUT)
    }

    pub(crate) fn open_with_timeouts(
        io: P,
        init_timeout: Duration,
        response_timeout: Duration,
    ) -> Result<Self, Error> {
        let mut ch = Ctaphid {
            io,
            cid: BROADCAST_CID,
            init: CtaphidInit {
                protocol_version: 0,
                device_version: (0, 0, 0),
                capabilities: 0,
            },
            response_timeout,
        };
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        ch.write_message(CMD_INIT, &nonce)?;
        // Replies to INIT come on the broadcast channel, so another
        // program's reply can arrive here too. Ours carries our nonce.
        let deadline = Instant::now() + init_timeout;
        let resp = loop {
            let (cmd, data) = ch.read_message(deadline)?;
            match cmd {
                CMD_INIT if data.len() >= 17 && data[..8] == nonce => break data,
                CMD_ERROR => {
                    return Err(Error::Transport {
                        code: data.first().copied().unwrap_or(0),
                    });
                }
                _ => continue,
            }
        };
        ch.cid.copy_from_slice(&resp[8..12]);
        ch.init = CtaphidInit {
            protocol_version: resp[12],
            device_version: (resp[13], resp[14], resp[15]),
            capabilities: resp[16],
        };
        if ch.init.capabilities & CAPABILITY_CBOR == 0 {
            return Err(Error::Unsupported(
                "this authenticator does not speak CTAP2 (a U2F-only key)",
            ));
        }
        Ok(ch)
    }

    /// Send one message and return the reply's command and data, calling
    /// `on_keepalive` for each keepalive that arrives first.
    fn transact(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(Keepalive),
    ) -> Result<(u8, Vec<u8>), Error> {
        self.write_message(cmd, data)?;
        let deadline = Instant::now() + self.response_timeout;
        loop {
            let (rcmd, rdata) = self.read_message(deadline)?;
            match rcmd {
                CMD_KEEPALIVE => on_keepalive(Keepalive::from(rdata.first().copied().unwrap_or(0))),
                CMD_ERROR => {
                    return Err(Error::Transport {
                        code: rdata.first().copied().unwrap_or(0),
                    });
                }
                _ => return Ok((rcmd, rdata)),
            }
        }
    }

    fn write_message(&mut self, cmd: u8, data: &[u8]) -> Result<(), Error> {
        if cmd != CMD_INIT && cmd != CMD_CBOR {
            return Err(Error::Protocol(format!(
                "refusing to send CTAPHID command {cmd:#04x}: only INIT and CBOR are sent"
            )));
        }
        if data.len() > MAX_MESSAGE {
            return Err(Error::Protocol(format!(
                "message of {} bytes is too long for CTAPHID (at most {MAX_MESSAGE})",
                data.len()
            )));
        }
        let mut pkt = [0u8; PACKET];
        pkt[..4].copy_from_slice(&self.cid);
        pkt[4] = 0x80 | cmd;
        pkt[5] = (data.len() >> 8) as u8;
        pkt[6] = data.len() as u8;
        let first = data.len().min(PACKET - 7);
        pkt[7..7 + first].copy_from_slice(&data[..first]);
        self.io.write_packet(&pkt)?;
        for (seq, chunk) in data[first..].chunks(PACKET - 5).enumerate() {
            let mut pkt = [0u8; PACKET];
            pkt[..4].copy_from_slice(&self.cid);
            // At most 128 chunks: checked against MAX_MESSAGE above.
            pkt[4] = seq as u8;
            pkt[5..5 + chunk.len()].copy_from_slice(chunk);
            self.io.write_packet(&pkt)?;
        }
        Ok(())
    }

    /// The next packet on our channel. Packets for other channels (other
    /// programs talking to the same key) are skipped.
    fn read_packet(&mut self, deadline: Instant) -> Result<[u8; PACKET], Error> {
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout);
            }
            match self.io.read_packet(left.min(READ_SLICE))? {
                Some(pkt) if pkt[..4] == self.cid => return Ok(pkt),
                _ => continue,
            }
        }
    }

    fn read_message(&mut self, deadline: Instant) -> Result<(u8, Vec<u8>), Error> {
        let first = self.read_packet(deadline)?;
        if first[4] & 0x80 == 0 {
            return Err(Error::Protocol(
                "CTAPHID: expected an initialization packet, got a continuation".into(),
            ));
        }
        let cmd = first[4] & 0x7f;
        let len = (usize::from(first[5]) << 8) | usize::from(first[6]);
        if len > MAX_MESSAGE {
            return Err(Error::Protocol(format!(
                "CTAPHID: the key announced a message of {len} bytes (at most {MAX_MESSAGE})"
            )));
        }
        let mut data = Vec::with_capacity(len);
        data.extend_from_slice(&first[7..7 + len.min(PACKET - 7)]);
        let mut seq = 0u8;
        while data.len() < len {
            let pkt = self.read_packet(deadline)?;
            if pkt[4] != seq {
                return Err(Error::Protocol(format!(
                    "CTAPHID: continuation out of order (got {:#04x}, expected {seq:#04x})",
                    pkt[4]
                )));
            }
            let n = (len - data.len()).min(PACKET - 5);
            data.extend_from_slice(&pkt[5..5 + n]);
            seq += 1;
        }
        Ok((cmd, data))
    }
}

impl<P: PacketIo> CborTransport for Ctaphid<P> {
    fn cbor(
        &mut self,
        request: &Request,
        on_keepalive: &mut dyn FnMut(Keepalive),
    ) -> Result<Vec<u8>, Error> {
        let (cmd, resp) = self.transact(CMD_CBOR, request.bytes(), on_keepalive)?;
        if cmd != CMD_CBOR {
            return Err(Error::Protocol(format!(
                "CTAPHID: expected a CBOR reply, got command {cmd:#04x}"
            )));
        }
        Ok(resp)
    }

    fn ctaphid_init(&self) -> Option<CtaphidInit> {
        Some(self.init)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::allow::CMD_GET_INFO;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// What the fake key's CBOR handler is given and returns: the request
    /// bytes in, keepalive statuses to send first and the reply out.
    pub(crate) type Handler = Box<dyn FnMut(&[u8]) -> (Vec<u8>, Vec<u8>) + Send>;

    /// The key's side of CTAPHID, in memory: reassembles what is written,
    /// answers INIT itself and hands CBOR messages to `handler`.
    pub(crate) struct FakeHid {
        handler: Handler,
        cid: [u8; 4],
        capabilities: u8,
        /// Packets waiting to be read.
        outbox: VecDeque<[u8; PACKET]>,
        /// A message being written: channel, command, announced length, data.
        partial: Option<([u8; 4], u8, usize, Vec<u8>)>,
        /// Put a packet for another channel in front of every reply.
        pub(crate) noise: bool,
        /// Answer INIT with another program's nonce first.
        pub(crate) foreign_init_first: bool,
        /// Every packet written, for the tests that look at framing.
        pub(crate) written: Arc<Mutex<Vec<[u8; PACKET]>>>,
    }

    impl FakeHid {
        pub(crate) fn new(handler: Handler) -> Self {
            FakeHid {
                handler,
                cid: [0x0a, 0x0b, 0x0c, 0x0d],
                capabilities: 0x05,
                outbox: VecDeque::new(),
                partial: None,
                noise: false,
                foreign_init_first: false,
                written: Arc::default(),
            }
        }

        pub(crate) fn u2f_only(mut self) -> Self {
            self.capabilities = 0x01;
            self
        }

        fn queue(&mut self, cid: [u8; 4], cmd: u8, data: &[u8]) {
            if self.noise {
                let mut other = [0x55u8; PACKET];
                other[..4].copy_from_slice(&[1, 2, 3, 4]);
                self.outbox.push_back(other);
            }
            let mut pkt = [0u8; PACKET];
            pkt[..4].copy_from_slice(&cid);
            pkt[4] = 0x80 | cmd;
            pkt[5] = (data.len() >> 8) as u8;
            pkt[6] = data.len() as u8;
            let first = data.len().min(PACKET - 7);
            pkt[7..7 + first].copy_from_slice(&data[..first]);
            self.outbox.push_back(pkt);
            for (seq, chunk) in data[first..].chunks(PACKET - 5).enumerate() {
                let mut pkt = [0u8; PACKET];
                pkt[..4].copy_from_slice(&cid);
                pkt[4] = seq as u8;
                pkt[5..5 + chunk.len()].copy_from_slice(chunk);
                self.outbox.push_back(pkt);
            }
        }

        fn message(&mut self, cid: [u8; 4], cmd: u8, data: Vec<u8>) {
            match cmd {
                CMD_INIT => {
                    assert_eq!(cid, BROADCAST_CID, "INIT goes to the broadcast channel");
                    if self.foreign_init_first {
                        let mut foreign = vec![0xeeu8; 8];
                        foreign.extend_from_slice(&[9, 9, 9, 9, 2, 0, 0, 0, 0x05]);
                        self.queue(BROADCAST_CID, CMD_INIT, &foreign);
                    }
                    let mut reply = data.clone();
                    reply.extend_from_slice(&self.cid);
                    reply.extend_from_slice(&[2, 5, 7, 4, self.capabilities]);
                    self.queue(BROADCAST_CID, CMD_INIT, &reply);
                }
                CMD_CBOR => {
                    assert_eq!(cid, self.cid, "CBOR goes to the allocated channel");
                    let (keepalives, reply) = (self.handler)(&data);
                    for k in keepalives {
                        self.queue(cid, CMD_KEEPALIVE, &[k]);
                    }
                    self.queue(cid, CMD_CBOR, &reply);
                }
                other => panic!("the client sent CTAPHID command {other:#04x}"),
            }
        }
    }

    impl PacketIo for FakeHid {
        fn write_packet(&mut self, packet: &[u8; PACKET]) -> Result<(), Error> {
            self.written.lock().unwrap().push(*packet);
            let cid: [u8; 4] = packet[..4].try_into().unwrap();
            if packet[4] & 0x80 != 0 {
                assert!(
                    self.partial.is_none(),
                    "a new message before the last ended"
                );
                let len = (usize::from(packet[5]) << 8) | usize::from(packet[6]);
                let first = len.min(PACKET - 7);
                self.partial = Some((cid, packet[4] & 0x7f, len, packet[7..7 + first].to_vec()));
            } else {
                let (pcid, _, len, data) = self.partial.as_mut().expect("continuation first");
                assert_eq!(*pcid, cid);
                let expected = (data.len() - (PACKET - 7)) / (PACKET - 5);
                assert_eq!(usize::from(packet[4]), expected, "sequence number");
                let n = (*len - data.len()).min(PACKET - 5);
                data.extend_from_slice(&packet[5..5 + n]);
            }
            if self.partial.as_ref().is_some_and(|p| p.3.len() == p.2) {
                let (cid, cmd, _, data) = self.partial.take().unwrap();
                self.message(cid, cmd, data);
            }
            Ok(())
        }

        fn read_packet(&mut self, _timeout: Duration) -> Result<Option<[u8; PACKET]>, Error> {
            Ok(self.outbox.pop_front())
        }
    }

    const SHORT: Duration = Duration::from_millis(40);

    fn open(hid: FakeHid) -> Result<Ctaphid<FakeHid>, Error> {
        Ctaphid::open_with_timeouts(hid, SHORT, SHORT)
    }

    fn echo() -> Handler {
        Box::new(|req| (vec![], [&[0u8][..], req].concat()))
    }

    #[test]
    fn init_allocates_a_channel_and_reads_the_capabilities() {
        let ch = open(FakeHid::new(echo())).unwrap();
        assert_eq!(ch.cid, [0x0a, 0x0b, 0x0c, 0x0d]);
        let init = ch.ctaphid_init().unwrap();
        assert_eq!(init.protocol_version, 2);
        assert_eq!(init.device_version, (5, 7, 4));
        assert_eq!(init.capabilities, 0x05);
        // One packet was written: INIT, on the broadcast channel, 8 bytes.
        let written = ch.io.written.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0][..7], [0xff, 0xff, 0xff, 0xff, 0x86, 0, 8]);
    }

    #[test]
    fn init_skips_another_programs_reply_and_other_channels() {
        let mut hid = FakeHid::new(echo());
        hid.foreign_init_first = true;
        hid.noise = true;
        let ch = open(hid).unwrap();
        assert_eq!(ch.cid, [0x0a, 0x0b, 0x0c, 0x0d]);
    }

    #[test]
    fn a_u2f_only_key_is_refused() {
        let e = open(FakeHid::new(echo()).u2f_only()).err().unwrap();
        assert!(matches!(e, Error::Unsupported(_)), "{e}");
    }

    #[test]
    fn a_silent_device_times_out() {
        struct Silent;
        impl PacketIo for Silent {
            fn write_packet(&mut self, _: &[u8; PACKET]) -> Result<(), Error> {
                Ok(())
            }
            fn read_packet(&mut self, t: Duration) -> Result<Option<[u8; PACKET]>, Error> {
                std::thread::sleep(t);
                Ok(None)
            }
        }
        let e = Ctaphid::open_with_timeouts(Silent, SHORT, SHORT)
            .err()
            .unwrap();
        assert!(matches!(e, Error::Timeout), "{e}");
    }

    #[test]
    fn a_short_message_fits_one_packet() {
        let mut ch = open(FakeHid::new(echo())).unwrap();
        let req = Request::new(CMD_GET_INFO, None).unwrap();
        let reply = ch.cbor(&req, &mut |_| {}).unwrap();
        assert_eq!(reply, [0x00, 0x04]);
        let written = ch.io.written.lock().unwrap();
        assert_eq!(written.len(), 2);
        assert_eq!(written[1][..8], [0x0a, 0x0b, 0x0c, 0x0d, 0x90, 0, 1, 0x04]);
        assert!(written[1][8..].iter().all(|b| *b == 0));
    }

    /// A request and a reply both long enough for continuation packets,
    /// with packets for another channel between the reply's packets.
    #[test]
    fn long_messages_are_split_and_reassembled() {
        use crate::cbor::int;
        use ciborium::value::Value;
        let mut hid = FakeHid::new(echo());
        hid.noise = true;
        let mut ch = open(hid).unwrap();
        // getAssertion with a 300-byte value: 5 continuation packets.
        let big: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let params = Value::Map(vec![(int(1), Value::Bytes(big))]);
        let req = Request::new(crate::allow::CMD_GET_ASSERTION, Some(&params)).unwrap();
        let reply = ch.cbor(&req, &mut |_| {}).unwrap();
        assert_eq!(reply[0], 0);
        assert_eq!(&reply[1..], req.bytes());

        let written = ch.io.written.lock().unwrap();
        let sent = &written[1..];
        let len = req.bytes().len();
        assert_eq!(sent.len(), 1 + (len - 57).div_ceil(59));
        assert_eq!(sent[0][4], 0x90);
        assert_eq!(usize::from(sent[0][5]) << 8 | usize::from(sent[0][6]), len);
        for (i, pkt) in sent[1..].iter().enumerate() {
            assert_eq!(pkt[..4], [0x0a, 0x0b, 0x0c, 0x0d]);
            assert_eq!(usize::from(pkt[4]), i, "continuation sequence");
        }
    }

    #[test]
    fn keepalives_are_reported_in_order_before_the_reply() {
        let handler: Handler = Box::new(|_| (vec![1, 2, 2, 9], vec![0x00]));
        let mut ch = open(FakeHid::new(handler)).unwrap();
        let req = Request::new(CMD_GET_INFO, None).unwrap();
        let mut seen = vec![];
        let reply = ch.cbor(&req, &mut |k| seen.push(k)).unwrap();
        assert_eq!(reply, [0x00]);
        assert_eq!(
            seen,
            [
                Keepalive::Processing,
                Keepalive::UserPresenceNeeded,
                Keepalive::UserPresenceNeeded,
                Keepalive::Other(9)
            ]
        );
    }

    /// Scripted packets, for replies the fake key above would never send.
    struct Script(VecDeque<[u8; PACKET]>);
    impl PacketIo for Script {
        fn write_packet(&mut self, _: &[u8; PACKET]) -> Result<(), Error> {
            Ok(())
        }
        fn read_packet(&mut self, _: Duration) -> Result<Option<[u8; PACKET]>, Error> {
            Ok(self.0.pop_front())
        }
    }

    fn scripted(packets: &[&[u8]]) -> Ctaphid<Script> {
        let packets = packets
            .iter()
            .map(|p| {
                let mut pkt = [0u8; PACKET];
                pkt[..p.len()].copy_from_slice(p);
                pkt
            })
            .collect();
        Ctaphid {
            io: Script(packets),
            cid: [1, 1, 1, 1],
            init: CtaphidInit {
                protocol_version: 2,
                device_version: (0, 0, 0),
                capabilities: 4,
            },
            response_timeout: SHORT,
        }
    }

    fn get_info(ch: &mut Ctaphid<Script>) -> Result<Vec<u8>, Error> {
        ch.cbor(&Request::new(CMD_GET_INFO, None).unwrap(), &mut |_| {})
    }

    #[test]
    fn a_transport_error_keeps_its_code() {
        let mut ch = scripted(&[&[1, 1, 1, 1, 0xbf, 0, 1, 0x06]]);
        let e = get_info(&mut ch).unwrap_err();
        assert!(matches!(e, Error::Transport { code: 0x06 }), "{e}");
    }

    #[test]
    fn malformed_framing_is_a_protocol_error() {
        // A continuation packet where a message should start.
        let mut ch = scripted(&[&[1, 1, 1, 1, 0x00, 1, 2, 3]]);
        assert!(matches!(get_info(&mut ch), Err(Error::Protocol(_))));
        // Continuations out of order (sequence 1 before 0).
        let mut ch = scripted(&[&[1, 1, 1, 1, 0x90, 0, 100], &[1, 1, 1, 1, 0x01]]);
        assert!(matches!(get_info(&mut ch), Err(Error::Protocol(_))));
        // A length no CTAPHID message can have.
        let mut ch = scripted(&[&[1, 1, 1, 1, 0x90, 0xff, 0xff]]);
        assert!(matches!(get_info(&mut ch), Err(Error::Protocol(_))));
        // A reply that is not CBOR.
        let mut ch = scripted(&[&[1, 1, 1, 1, 0x83, 0, 1, 0]]);
        assert!(matches!(get_info(&mut ch), Err(Error::Protocol(_))));
        // A message that stops half way: the wait ends in a timeout.
        let mut ch = scripted(&[&[1, 1, 1, 1, 0x90, 0, 100]]);
        assert!(matches!(get_info(&mut ch), Err(Error::Timeout)));
    }

    #[test]
    fn only_init_and_cbor_are_ever_written() {
        let mut ch = scripted(&[]);
        for cmd in [0x01u8, 0x03, 0x08, 0x11, 0x3b, 0x3f, 0x40] {
            assert!(matches!(
                ch.write_message(cmd, &[]),
                Err(Error::Protocol(_))
            ));
        }
        assert!(
            ch.write_message(CMD_CBOR, &vec![0; MAX_MESSAGE + 1])
                .is_err()
        );
        assert!(ch.write_message(CMD_CBOR, &vec![0; MAX_MESSAGE]).is_ok());
    }
}

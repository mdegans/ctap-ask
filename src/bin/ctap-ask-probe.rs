//! ctap-ask-probe: does a USB FIDO2 key give assertions without a touch,
//! and is a PIN needed once or every time?
//!
//! Built on the library's public API and nothing else, so it can do only
//! what the library can: ask for assertions, read getInfo and obtain PIN
//! tokens. It never creates, deletes or changes a credential, never sets
//! or changes a PIN, never resets a key.

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use ctap_ask::{
    Assertion, AssertionRequest, Authenticator, ClientData, CredentialId, Device, Error, Info,
    Keepalive, Pin, PinToken, PublicKey,
};
use rand_core::{OsRng, RngCore};
use std::time::Instant;
use zeroize::Zeroizing;

/// The probe does not prompt for the PIN when this few attempts are left.
const PIN_RETRY_FLOOR: u32 = ctap_ask::Authenticator::DEFAULT_PIN_RETRY_FLOOR;

#[derive(Parser)]
#[command(
    version,
    about = "Probe a USB FIDO2 key for presence-free and PIN-once assertions (assertions only; never writes to the key)"
)]
struct Cli {
    /// Which authenticator to use when more than one is connected (index from `info`).
    #[arg(long, global = true)]
    device: Option<usize>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List connected FIDO authenticators and print getInfo for each.
    Info,
    /// Ask for one assertion.
    Assert {
        #[command(flatten)]
        target: Target,
        /// Send up=false (no touch).
        #[arg(long)]
        no_touch: bool,
        /// Obtain a PIN/UV token (prompts for the PIN) and ask for user verification.
        #[arg(long)]
        uv: bool,
    },
    /// Run the touch x UV combinations in sequence and print one table.
    Matrix {
        #[command(flatten)]
        target: Target,
    },
}

#[derive(clap::Args)]
struct Target {
    /// The relying party ID the passkey was created for (e.g. `example.org`).
    #[arg(long)]
    rp_id: String,
    /// Credential id (base64url or hex) to put in the allow list. Without it, discoverable credentials are used.
    #[arg(long)]
    credential_id: Option<String>,
    /// The credential's public key (COSE_Key as base64url or hex) to verify signatures.
    #[arg(long)]
    public_key: Option<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let devices = ctap_ask::devices()?;
    match cli.cmd {
        Cmd::Info => cmd_info(&devices),
        Cmd::Assert {
            target,
            no_touch,
            uv,
        } => {
            let t = Prepared::new(&target)?;
            let mut key = open_one(&devices, cli.device)?;
            cmd_assert(&mut key, &t, !no_touch, uv)
        }
        Cmd::Matrix { target } => {
            let t = Prepared::new(&target)?;
            let mut key = open_one(&devices, cli.device)?;
            cmd_matrix(&mut key, &t)
        }
    }
}

struct Prepared {
    rp_id: String,
    credential_id: Option<Vec<u8>>,
    public_key: Option<PublicKey>,
}

impl Prepared {
    fn new(t: &Target) -> Result<Self> {
        // A bare domain. This also keeps the client data below valid JSON
        // without an escaper.
        let domain_like = !t.rp_id.is_empty()
            && t.rp_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !domain_like {
            bail!("--rp-id must be a bare domain such as `example.org`, not a URL");
        }
        Ok(Prepared {
            rp_id: t.rp_id.clone(),
            credential_id: t
                .credential_id
                .as_deref()
                .map(decode_b64url_or_hex)
                .transpose()
                .context("--credential-id")?,
            public_key: t
                .public_key
                .as_deref()
                .map(|s| -> Result<PublicKey> { Ok(PublicKey::parse(&decode_b64url_or_hex(s)?)?) })
                .transpose()
                .context("--public-key")?,
        })
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Decode base64url (padded or not) or hex.
fn decode_b64url_or_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if let Some(b) = decode_hex(s) {
        return Ok(b);
    }
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| anyhow!("not valid base64url or hex: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn open_one(devices: &[Device], index: Option<usize>) -> Result<Authenticator> {
    let device = match (index, devices.len()) {
        (_, 0) => return Err(Error::NoDevice.into()),
        (Some(i), _) => devices
            .get(i)
            .ok_or_else(|| anyhow!("no device #{i}; run `info` to list them"))?,
        (None, 1) => &devices[0],
        (None, n) => bail!("{n} FIDO authenticators found; pick one with --device N (see `info`)"),
    };
    Ok(device.open()?)
}

// ---- info ----------------------------------------------------------------

fn cmd_info(devices: &[Device]) -> Result<()> {
    if devices.is_empty() {
        println!("No FIDO authenticators found (HID usage page 0xF1D0).");
        println!(
            "If a key is plugged in: on Linux this usually means /dev/hidraw* is not readable by you; see the README."
        );
        return Ok(());
    }
    for (i, d) in devices.iter().enumerate() {
        println!(
            "#{i}: {} {} (vid {:04x} pid {:04x}) at {}",
            d.manufacturer(),
            d.product(),
            d.vendor_id(),
            d.product_id(),
            d.path()
        );
        let mut key = match d.open() {
            Ok(key) => key,
            Err(e) => {
                println!("  cannot open: {e}");
                continue;
            }
        };
        if let Some(init) = key.ctaphid() {
            let (a, b, c) = init.device_version;
            println!(
                "  CTAPHID: protocol {} device version {a}.{b}.{c} capabilities {:#04x} (WINK={} CBOR={} NMSG={})",
                init.protocol_version,
                init.capabilities,
                init.capabilities & 1 != 0,
                init.capabilities & 4 != 0,
                init.capabilities & 8 != 0
            );
        }
        match key.get_info() {
            Ok(info) => print_info(&info),
            Err(e) => println!("  getInfo failed: {e}"),
        }
    }
    Ok(())
}

fn print_info(info: &Info) {
    for field in info.fields() {
        let rendered = match (field.key, info.aaguid, info.firmware_version) {
            (0x03, Some(aaguid), _) => dashed_hex(&aaguid),
            (0x0e, _, Some(n)) => format!(
                "{n} (as bytes: {}.{}.{})",
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            ),
            (0x04, _, _) => info
                .options
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
            _ => field.value.clone(),
        };
        println!("  {:<32} {rendered}", field.name);
    }
    let opt = |n: &str| match info.option(n) {
        Some(true) => "true",
        Some(false) => "false",
        None => "absent",
    };
    println!(
        "  summary: versions {:?}; clientPin={} uv={} up={} alwaysUv={} pinUvAuthToken={} rk={}",
        info.versions,
        opt("clientPin"),
        opt("uv"),
        opt("up"),
        opt("alwaysUv"),
        opt("pinUvAuthToken"),
        opt("rk")
    );
}

/// The 8-4-4-4-12 form an AAGUID is usually written in. An AAGUID names
/// the authenticator's model (every key of that model has the same one),
/// not the key or its owner.
fn dashed_hex(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

// ---- one assertion -------------------------------------------------------

/// How user verification is obtained on this key.
enum UvMode {
    Pin,
    BuiltIn,
}

fn uv_mode(info: &Info) -> Result<UvMode> {
    match (info.option("clientPin"), info.option("uv")) {
        (Some(true), _) => Ok(UvMode::Pin),
        (_, Some(true)) => Ok(UvMode::BuiltIn),
        (Some(false), _) => bail!(
            "no PIN is set on this key, so it cannot do UV. This tool will not set one (use your key manager)."
        ),
        _ => bail!("this key supports neither a PIN nor built-in UV"),
    }
}

/// Read the PIN from the terminal without echo, after asking the key how
/// many attempts are left. Refuses to prompt when few are.
fn ask_pin(key: &mut Authenticator) -> Result<Pin> {
    let retries = match key.pin_retries() {
        Ok(r) => Some(r.retries),
        Err(e) => {
            eprintln!("note: getPinRetries failed: {e}");
            None
        }
    };
    if let Some(n) = retries {
        if n < PIN_RETRY_FLOOR {
            bail!(
                "only {n} PIN attempts left on this key; refusing to risk blocking it. Check the PIN in your key manager first."
            );
        }
    }
    let prompt = match retries {
        Some(n) => format!("Key PIN ({n} attempts left before the PIN blocks; input hidden): "),
        None => "Key PIN (input hidden): ".to_string(),
    };
    let typed = Zeroizing::new(rpassword::prompt_password(prompt)?);
    let pin = Zeroizing::new(typed.trim_end_matches(['\r', '\n']).to_string());
    // Refuses a PIN the key could not accept, before it costs an attempt.
    Ok(Pin::new(pin)?)
}

struct Outcome {
    client_data_json: String,
    client_data: ClientData,
    result: Result<Assertion, Error>,
    others: Vec<Assertion>,
    asked_for_touch: bool,
}

fn client_data(rp_id: &str) -> (String, ClientData) {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    // `rp_id` was checked to be a bare domain, and base64url has no
    // character JSON escapes.
    let json = format!(
        r#"{{"type":"ctap-ask.probe","challenge":"{}","origin":"{rp_id}"}}"#,
        URL_SAFE_NO_PAD.encode(challenge)
    );
    let data = ClientData::Raw(json.clone().into_bytes());
    (json, data)
}

fn assert_once(
    key: &mut Authenticator,
    t: &Prepared,
    up: bool,
    token: Option<&PinToken>,
    built_in_uv: bool,
) -> Result<Outcome> {
    let (client_data_json, client_data) = client_data(&t.rp_id);
    let mut request = AssertionRequest::new(t.rp_id.as_str(), client_data.clone())
        .user_presence(up)
        .built_in_uv(built_in_uv);
    if let Some(id) = &t.credential_id {
        request = request.allow_credential(id.clone());
    }
    if let Some(token) = token {
        request = request.pin_token(token);
    }
    let mut asked_for_touch = false;
    let result = key.get_assertion_with(&request, |status| {
        if status == Keepalive::UserPresenceNeeded && !asked_for_touch {
            asked_for_touch = true;
            if up {
                eprintln!("  ... the key is blinking: touch it now");
            } else {
                eprintln!(
                    "  ... the key is asking for a touch although up=false was sent (touch it, or wait for the timeout)"
                );
            }
        }
    });
    // A refusal by the key is a result to report; anything else (I/O, a
    // malformed reply) is a failure of the run.
    let result = match result {
        Err(e) if e.status().is_none() => return Err(e.into()),
        other => other,
    };
    let mut others = vec![];
    if let Ok(a) = &result {
        let n = a.number_of_credentials.unwrap_or(1);
        if n > 16 {
            eprintln!("  {n} credentials answered; showing the first 16 only");
        }
        for _ in 1..n.min(16) {
            match key.get_next_assertion() {
                Ok(next) => others.push(next),
                Err(e) => {
                    eprintln!("  getNextAssertion: {e}");
                    break;
                }
            }
        }
    }
    Ok(Outcome {
        client_data_json,
        client_data,
        result,
        others,
        asked_for_touch,
    })
}

fn verify_str(t: &Prepared, o: &Outcome, a: &Assertion) -> String {
    match &t.public_key {
        None => "n/a (no --public-key)".into(),
        Some(pk) => match pk.verify(&a.authenticator_data, &o.client_data, &a.signature) {
            Ok(true) => "VERIFIES".into(),
            Ok(false) => "DOES NOT VERIFY".into(),
            Err(e) => format!("cannot verify: {e}"),
        },
    }
}

fn print_assertion(t: &Prepared, o: &Outcome, a: &Assertion, indent: &str) {
    let ad = &a.authenticator_data;
    println!("{indent}flags            {}", ad.flags());
    println!("{indent}sign counter     {}", ad.sign_count());
    println!(
        "{indent}rpIdHash         {}",
        if ad.rp_id_matches(&t.rp_id) {
            "matches SHA-256(rp id)"
        } else {
            "DOES NOT MATCH SHA-256(rp id)"
        }
    );
    let cred = a
        .credential_id
        .as_ref()
        .map(CredentialId::as_bytes)
        .or(t.credential_id.as_deref())
        .map(|c| URL_SAFE_NO_PAD.encode(c))
        .unwrap_or_else(|| "(none returned)".into());
    println!("{indent}credential id    {cred}");
    match &a.user {
        Some(u) => println!(
            "{indent}user handle      {}{}",
            URL_SAFE_NO_PAD.encode(&u.id),
            u.name
                .as_deref()
                .map(|n| format!(" (name {n:?})"))
                .unwrap_or_default()
        ),
        None => println!("{indent}user handle      (none returned)"),
    }
    println!(
        "{indent}signature        {} bytes",
        a.signature.as_bytes().len()
    );
    println!("{indent}signature check  {}", verify_str(t, o, a));
    println!(
        "{indent}authData (b64u)  {}",
        URL_SAFE_NO_PAD.encode(ad.as_bytes())
    );
    println!(
        "{indent}signature (b64u) {}",
        URL_SAFE_NO_PAD.encode(a.signature.as_bytes())
    );
}

fn cmd_assert(key: &mut Authenticator, t: &Prepared, up: bool, want_uv: bool) -> Result<()> {
    let info = key.get_info()?;
    let mut token = None;
    let mut built_in_uv = false;
    if want_uv {
        match uv_mode(&info)? {
            UvMode::Pin => {
                let pin = ask_pin(key)?;
                match key.pin_token(&pin, &t.rp_id) {
                    Ok(tk) => token = Some(tk),
                    Err(e) => bail!("the key refused the PIN token request: {e}{}", hint(&e)),
                }
            }
            UvMode::BuiltIn => built_in_uv = true,
        }
    }
    if up {
        println!("Touch the key when it blinks.");
    }
    let o = assert_once(key, t, up, token.as_ref(), built_in_uv)?;
    println!("rp id            {}", t.rp_id);
    println!(
        "sent             up={up} uv={}",
        if token.is_some() {
            "PIN token"
        } else if built_in_uv {
            "uv option"
        } else {
            "none"
        }
    );
    println!("clientDataJSON   {}", o.client_data_json);
    match &o.result {
        Err(e) => {
            println!("result           REFUSED: {e}{}", hint(e));
            std::process::exit(2);
        }
        Ok(a) => {
            println!(
                "result           ASSERTION returned{}",
                if o.asked_for_touch && !up {
                    " (after the key asked for a touch)"
                } else {
                    ""
                }
            );
            if let Some(n) = a.number_of_credentials {
                println!("credentials      {n} for this RP ID (listed below)");
            }
            print_assertion(t, &o, a, "  ");
            for (i, other) in o.others.iter().enumerate() {
                println!("  -- credential {} --", i + 2);
                print_assertion(t, &o, other, "  ");
            }
        }
    }
    Ok(())
}

/// A sentence for the refusals a person running this tool will meet.
fn hint(e: &Error) -> String {
    let text = match e {
        Error::NoCredentials { .. } => {
            "the key holds no credential for this RP ID that this request may see. Check the RP \
             ID (the bare host name, e.g. `example.org`). A passkey created with credProtect \
             level 2 or 3 is invisible to a discoverable (no --credential-id) request without \
             UV: try --uv, or pass --credential-id."
        }
        Error::UserPresence { .. } => "the key refused, or the touch was not given in time.",
        Error::PinInvalid { .. } => {
            "this attempt counted against the key's retry counter; the tool will not retry on \
             its own."
        }
        Error::PinBlocked { .. } => "only a reset (which this tool never does) clears it.",
        Error::PinTokenRejected { .. } => {
            "expired, consumed by an earlier touched assertion, or bound to another RP ID."
        }
        Error::PinRequired { .. } => "alwaysUv is on, or the credential is protected.",
        Error::PinNotSet { .. } => "this tool will not set one.",
        Error::Ctap(status) if [0x2b, 0x2c].contains(&status.code()) => {
            "the key does not accept this combination of options."
        }
        _ => return String::new(),
    };
    format!("\n  -> {text}")
}

// ---- matrix --------------------------------------------------------------

struct Row {
    label: &'static str,
    up: bool,
    uv: &'static str,
    result: String,
    flags: String,
    counter: String,
    verified: String,
}

impl Row {
    fn skipped(label: &'static str, up: bool, result: String) -> Self {
        Row {
            label,
            up,
            uv: "-",
            result,
            flags: "-".into(),
            counter: "-".into(),
            verified: "-".into(),
        }
    }
}

fn row_from(
    label: &'static str,
    up: bool,
    uv: &'static str,
    o: Result<Outcome>,
    t: &Prepared,
) -> Row {
    let mut row = Row::skipped(label, up, String::new());
    row.uv = uv;
    match o {
        Err(e) => row.result = format!("tool error: {e:#}"),
        Ok(o) => match &o.result {
            Err(e) => {
                row.result = match e.status() {
                    Some(status) => format!("REFUSED {status}"),
                    None => format!("REFUSED {e}"),
                }
            }
            Ok(a) => {
                row.result = if o.asked_for_touch && !up {
                    "assertion (key asked for touch!)".into()
                } else {
                    "assertion".into()
                };
                let flags = a.authenticator_data.flags();
                row.flags = format!(
                    "UP={} UV={}",
                    u8::from(flags.user_present()),
                    u8::from(flags.user_verified())
                );
                row.counter = a.authenticator_data.sign_count().to_string();
                row.verified = verify_str(t, &o, a);
            }
        },
    }
    println!("  -> {}", row.result);
    row
}

fn cmd_matrix(key: &mut Authenticator, t: &Prepared) -> Result<()> {
    let info = key.get_info()?;
    let mut rows = vec![];

    println!("[1] touch, no UV. Touch the key when it blinks.");
    let o = assert_once(key, t, true, None, false);
    rows.push(row_from("1  touch, no UV", true, "none", o, t));

    println!("[2] no touch, no UV. Do NOT touch the key.");
    let o = assert_once(key, t, false, None, false);
    rows.push(row_from("2  no touch, no UV", false, "none", o, t));

    match uv_mode(&info) {
        Err(e) => {
            println!("UV rows skipped: {e:#}");
            rows.push(Row::skipped("3-4 UV rows", false, format!("skipped: {e}")));
        }
        Ok(UvMode::BuiltIn) => {
            println!(
                "This key has built-in UV and no PIN: UV rows send uv=true each time (no token to reuse)."
            );
            println!("[3] touch, UV. Verify on the key (e.g. fingerprint) when asked.");
            let o = assert_once(key, t, true, None, true);
            rows.push(row_from("3  touch, built-in UV", true, "uv option", o, t));
            println!("[4] no touch, UV. Verify on the key when asked.");
            let o = assert_once(key, t, false, None, true);
            rows.push(row_from(
                "4  no touch, built-in UV",
                false,
                "uv option",
                o,
                t,
            ));
        }
        Ok(UvMode::Pin) => {
            println!(
                "The UV rows need the key's PIN once; it is held in memory only for this run."
            );
            let pin = ask_pin(key)?;
            uv_rows(key, t, &pin, &mut rows);
        }
    }

    println!();
    println!(
        "rp id {} | credential {} | key {}",
        t.rp_id,
        if t.credential_id.is_some() {
            "from --credential-id (allow list)"
        } else {
            "discoverable (no allow list)"
        },
        info.versions.join(",")
    );
    let w = rows.iter().map(|r| r.label.len()).max().unwrap_or(10);
    println!(
        "{:<w$} | {:<5} | {:<26} | {:<9} | {:<7} | {:<34} | signature",
        "row", "up", "uv", "flags", "counter", "result"
    );
    println!("{}", "-".repeat(w + 110));
    for r in &rows {
        println!(
            "{:<w$} | {:<5} | {:<26} | {:<9} | {:<7} | {:<34} | {}",
            r.label, r.up, r.uv, r.flags, r.counter, r.result, r.verified
        );
    }
    Ok(())
}

fn uv_rows(key: &mut Authenticator, t: &Prepared, pin: &Pin, rows: &mut Vec<Row>) {
    let skip = |rows: &mut Vec<Row>, label: &'static str, up: bool, why: &Error| {
        println!("  -> skipped: token refused: {why}{}", hint(why));
        rows.push(Row::skipped(label, up, "skipped (see above)".into()));
    };

    // Token A: touched assertions.
    println!("[3a] touch, UV with a new PIN token A. Touch the key when it blinks.");
    match key.pin_token(pin, &t.rp_id) {
        Err(why) => {
            skip(rows, "3a touch, UV (new token A)", true, &why);
            // After a wrong or blocked PIN, or one the library held back
            // for the retry counter, no further PIN attempt is made.
            if matches!(
                why,
                Error::PinInvalid { .. }
                    | Error::PinBlocked { .. }
                    | Error::PinAuthBlocked { .. }
                    | Error::PinRetriesLow { .. }
            ) {
                println!("Stopping the UV rows so no further PIN attempt is made.");
                return;
            }
            skip(rows, "3b touch, UV (token A again)", true, &why);
        }
        Ok(tk) => {
            let o = assert_once(key, t, true, Some(&tk), false);
            rows.push(row_from(
                "3a touch, UV (new token A)",
                true,
                "PIN token A",
                o,
                t,
            ));
            println!(
                "[3b] touch, UV, same token A again (spec: a touched assertion consumes it). Touch the key if it blinks."
            );
            let o = assert_once(key, t, true, Some(&tk), false);
            rows.push(row_from(
                "3b touch, UV (token A again)",
                true,
                "PIN token A, 2nd use",
                o,
                t,
            ));
        }
    }

    // Token B: silent assertions, then one touched.
    println!("[4a] no touch, UV with a new PIN token B. Do NOT touch the key.");
    match key.pin_token(pin, &t.rp_id) {
        Err(why) => {
            skip(rows, "4a no touch, UV (new token B)", false, &why);
            skip(rows, "4b no touch, UV (token B again)", false, &why);
            skip(rows, "4c touch, UV (token B, 3rd use)", true, &why);
        }
        Ok(tk) => {
            let born = Instant::now();
            let o = assert_once(key, t, false, Some(&tk), false);
            rows.push(row_from(
                "4a no touch, UV (new token B)",
                false,
                "PIN token B",
                o,
                t,
            ));
            println!("[4b] no touch, UV, same token B again. Do NOT touch the key.");
            let o = assert_once(key, t, false, Some(&tk), false);
            rows.push(row_from(
                "4b no touch, UV (token B again)",
                false,
                "PIN token B, 2nd use",
                o,
                t,
            ));
            println!(
                "[4c] touch, UV, token B a third time ({}s old). Touch the key when it blinks.",
                born.elapsed().as_secs()
            );
            let o = assert_once(key, t, true, Some(&tk), false);
            rows.push(row_from(
                "4c touch, UV (token B, 3rd use)",
                true,
                "PIN token B, 3rd use",
                o,
                t,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_decode_from_hex_and_base64url() {
        assert_eq!(decode_b64url_or_hex("c1c2").unwrap(), [0xc1, 0xc2]);
        assert_eq!(decode_b64url_or_hex(" wcI= ").unwrap(), [0xc1, 0xc2]);
        assert_eq!(decode_b64url_or_hex("wcI").unwrap(), [0xc1, 0xc2]);
        assert_eq!(decode_b64url_or_hex("_-8").unwrap(), [0xff, 0xef]);
        assert!(decode_b64url_or_hex("not base64!").is_err());
    }

    #[test]
    fn the_rp_id_must_be_a_bare_domain() {
        let target = |rp: &str| Target {
            rp_id: rp.into(),
            credential_id: None,
            public_key: None,
        };
        assert!(Prepared::new(&target("example.org")).is_ok());
        for bad in ["", "https://example.org", "example.org/path", "a\"b"] {
            assert!(Prepared::new(&target(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn client_data_is_json_and_fresh() {
        let (a, data) = client_data("example.org");
        let (b, _) = client_data("example.org");
        assert_ne!(a, b);
        assert!(a.starts_with(r#"{"type":"ctap-ask.probe","challenge":""#));
        assert!(a.ends_with(r#"","origin":"example.org"}"#));
        assert_eq!(data, ClientData::Raw(a.into_bytes()));
    }

    #[test]
    fn aaguid_formatting() {
        let b: [u8; 16] = core::array::from_fn(|i| i as u8);
        assert_eq!(dashed_hex(&b), "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }
}

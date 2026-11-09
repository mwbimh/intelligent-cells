use serde_json::{Map, Value, json};
use std::io::{IsTerminal, Write};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl LogFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err("log format must be text or json".into()),
        }
    }
}

pub fn emit(event: &Value, format: LogFormat) {
    let line = match format {
        LogFormat::Text => format_event_colored(
            event,
            use_color(
                std::io::stderr().is_terminal(),
                std::env::var_os("NO_COLOR").is_some(),
                std::env::var("TERM").ok().as_deref(),
            ),
        ),
        LogFormat::Json => format_json(event),
    };
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

// Whitespace, terminal controls and Unicode direction/format controls cannot
// create extra lines or masquerade as field delimiters. Limit by characters.
fn safe(value: &str) -> String {
    let mut chars = value.chars();
    let mut out = String::new();
    for c in chars.by_ref().take(120) {
        if c.is_control()
            || c.is_whitespace()
            || matches!(c,
            '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' |
            '\u{2060}'..='\u{206f}' | '\u{feff}' | '=' | '[' | ']')
        {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

fn error_code(event: &Value) -> Option<&str> {
    event
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .or_else(|| event.get("errorCode").and_then(Value::as_str))
        .or_else(|| event.get("code").and_then(Value::as_str))
}

fn error_description(code: &str) -> &'static str {
    match code {
        "TLS_ERROR" => "TLS connection failed",
        "IO_ERROR" => "I/O failed",
        "PEER_UNAVAILABLE" => "Peer unavailable",
        "IDENTITY_MISMATCH" => "Node identity mismatch",
        "UNTRUSTED_IDENTITY" | "UNTRUSTED_CA" => "Node identity untrusted",
        "PAIRING_DENIED" => "Pairing denied",
        "PAIRING_LIMIT" => "Pairing limit reached",
        "MASTER_DENIED" | "PEER_DENIED" => "Node not authorized",
        "TOOL_DENIED" => "Tool not authorized",
        "PATH_DENIED" | "DIRECTORY_DENIED" | "WORKSPACE_DENIED" | "EACCES" => "Access denied",
        "TIMEOUT" | "TASK_TIMEOUT" => "Operation timed out",
        "CANCELLED" | "TASK_CANCELLED" => "Task cancelled",
        "BUSY" => "Node busy",
        "NODE_STOPPING" => "Node stopping",
        "ENOENT" => "Target not found",
        "INVALID_CONFIG" => "Invalid configuration",
        "INVALID_JSON" => "Invalid message format",
        "INVALID_ARGS" => "Invalid arguments",
        "INVALID_TASK" => "Invalid task arguments",
        "PEER_NOT_FOUND" => "Peer not registered; pair first",
        "TASK_PENDING" => "Task pending",
        "OUTCOME_UNKNOWN" | "UNCERTAIN_SIDE_EFFECT" => "Outcome unknown; verify first",
        _ => "Operation failed; check error code",
    }
}

fn event_info(event: &Value) -> (&'static str, &'static str) {
    let failed = error_code(event).is_some()
        || event["ok"].as_bool() == Some(false)
        || matches!(
            event["status"].as_str(),
            Some("failed" | "error" | "rejected")
        );
    let outgoing = event["direction"].as_str() == Some("outgoing");
    let description = match event["event"].as_str().unwrap_or("") {
        "node_ready" => "Node ready",
        "node_stopped" => "Node stopped",
        "pairing_requested" => "Servant join requested; awaiting approval",
        "pairing_submitted" => "Join request submitted to master",
        "pairing_approved" => "Join request approved; awaiting servant confirmation",
        "pairing_rejected" => "Join request rejected",
        "pairing_completed" => "Pairing completed on both sides",
        "pairing_confirmed" => "Pairing confirmed",
        "peer_unpaired" => "Peer unpaired",
        "peer_registered" => "Servant registered",
        "master_authorized" => "Master authorized",
        "task_started" if outgoing => "Remote task requested",
        "task_started" => "Task request received",
        "task_finished" if failed && outgoing => "Remote call failed",
        "task_finished" if failed => "Task execution failed",
        "task_finished" if event["exitCode"].as_i64().is_some_and(|code| code != 0) => {
            "Task finished; command exited unsuccessfully"
        }
        "task_finished" if event["replayed"].as_bool() == Some(true) => "Saved result reused",
        "task_finished" if event["background"].as_bool() == Some(true) => "Task submitted",
        "task_finished" if event["outcomeUnknown"].as_bool() == Some(true) => {
            "Task outcome unknown"
        }
        "task_finished" if outgoing => "Remote call completed",
        "task_finished" => "Task execution completed",
        "connection_error" => "Peer connection failed",
        "pairing_connection_error" => "Pairing connection failed",
        "operator_command" if failed => "Operator command failed",
        "operator_command" => "Processing operator command",
        "operator_ready" => "Operator ready",
        "audit_error" => "Audit log write failed",
        _ => "Unknown event",
    };
    let level = if failed
        || matches!(
            event["event"].as_str(),
            Some("audit_error" | "connection_error" | "pairing_connection_error")
        ) {
        "ERROR"
    } else if event["exitCode"].as_i64().is_some_and(|code| code != 0)
        || event["outcomeUnknown"].as_bool() == Some(true)
        || matches!(
            event["event"].as_str(),
            Some("pairing_rejected" | "peer_unpaired")
        )
    {
        "WARN"
    } else {
        "INFO"
    };
    (level, description)
}

fn timestamp(millis: u64) -> String {
    let seconds: libc::time_t = match (millis / 1000).try_into() {
        Ok(value) => value,
        Err(_) => return "Invalid time".into(),
    };
    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    // localtime_r initializes only the caller-owned tm and does not share a buffer.
    let local = unsafe {
        if libc::localtime_r(&seconds, local.as_mut_ptr()).is_null() {
            return "Invalid time".into();
        }
        local.assume_init()
    };
    let offset = local.tm_gmtoff;
    let absolute = offset.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}{}{:02}:{:02}",
        i64::from(local.tm_year) + 1900,
        local.tm_mon + 1,
        local.tm_mday,
        local.tm_hour,
        local.tm_min,
        local.tm_sec,
        millis % 1000,
        if offset < 0 { '-' } else { '+' },
        absolute / 3600,
        absolute % 3600 / 60
    )
}

// Explicit scalar schema shared by JSON and terminal output; payloads and
// arbitrary error messages are never serialized here.
fn sanitized(event: &Value) -> Value {
    let (level, description) = event_info(event);
    let mut out = Map::new();
    out.insert(
        "timestamp".into(),
        json!(event["timestamp"].as_u64().unwrap_or(0)),
    );
    out.insert("level".into(), json!(level));
    out.insert("message".into(), json!(description));
    for key in [
        "event",
        "nodeId",
        "peerId",
        "taskId",
        "requestId",
        "tool",
        "direction",
        "status",
        "command",
        "host",
        "pairingHost",
        "remoteAddr",
    ] {
        if let Some(value) = event[key].as_str() {
            out.insert(key.into(), json!(safe(value)));
        }
    }
    for key in [
        "port",
        "pairingPort",
        "peerCount",
        "grantCount",
        "toolCount",
        "elapsedMs",
    ] {
        if let Some(value) = event[key].as_u64() {
            out.insert(key.into(), json!(value));
        }
    }
    for key in ["outcomeUnknown", "replayed", "background", "ok"] {
        if let Some(value) = event[key].as_bool() {
            out.insert(key.into(), json!(value));
        }
    }
    if let Some(code) = event["exitCode"].as_i64() {
        out.insert("exitCode".into(), json!(code));
    }
    if let Some(code) = error_code(event) {
        out.insert("errorCode".into(), json!(safe(code)));
        out.insert("errorDescription".into(), json!(error_description(code)));
    }
    Value::Object(out)
}

pub fn format_json(event: &Value) -> String {
    sanitized(event).to_string()
}

fn use_color(is_terminal: bool, no_color: bool, term: Option<&str>) -> bool {
    is_terminal && !no_color && term != Some("dumb")
}

fn styled(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\u{1b}[{code}m{text}\u{1b}[0m")
    } else {
        text.to_owned()
    }
}

pub fn format_event(event: &Value) -> String {
    format_event_colored(event, false)
}

pub fn format_event_colored(event: &Value, color: bool) -> String {
    // Only sanitized scalar values may enter styled terminal segments.
    let event = sanitized(event);
    let level = event["level"].as_str().unwrap_or("INFO");
    let level_color = match level {
        "ERROR" => "31",
        "WARN" => "33",
        _ => "32",
    };
    let mut line = format!(
        "{} {} {} {}",
        styled(
            &timestamp(event["timestamp"].as_u64().unwrap_or(0)),
            "90",
            color
        ),
        styled(level, level_color, color),
        styled(
            &format!("[{}]", event["nodeId"].as_str().unwrap_or("-")),
            "36",
            color
        ),
        styled(
            event["message"].as_str().unwrap_or("Unknown event"),
            "1",
            color
        )
    );
    match event["direction"].as_str() {
        Some("outgoing") => line.push_str(&styled(" →", "36", color)),
        Some("incoming") => line.push_str(&styled(" ←", "36", color)),
        _ => {}
    }
    let mut field = |label: &str, value: &str, code: &str| {
        line.push(' ');
        line.push_str(label);
        line.push('=');
        line.push_str(&styled(value, code, color));
    };
    for (key, label, code) in [
        ("peerId", "peer", "36"),
        ("taskId", "task", "34"),
        ("requestId", "request", "34"),
        ("tool", "tool", "35"),
        ("command", "command", "35"),
    ] {
        if let Some(value) = event[key].as_str() {
            let value = if matches!(key, "peerId" | "taskId" | "requestId") {
                let prefix: String = value.chars().take(12).collect();
                if value.chars().count() > 12 {
                    format!("{prefix}…")
                } else {
                    prefix
                }
            } else {
                value.to_owned()
            };
            field(label, &value, code);
        }
    }
    if let Some(host) = event["host"].as_str() {
        let address = match event["port"].as_u64() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        field("listen", &address, "36");
    } else if let Some(port) = event["port"].as_u64() {
        field("port", &port.to_string(), "36");
    }
    if let Some(address) = event["remoteAddr"].as_str() {
        field("remote", address, "36");
    }
    if event["pairingPort"].as_u64() == Some(0) {
        field("pairing", "disabled", "90");
    } else if let Some(host) = event["pairingHost"].as_str() {
        let address = match event["pairingPort"].as_u64() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        field("pairing", &address, "36");
    } else if let Some(port) = event["pairingPort"].as_u64() {
        field("pairingPort", &port.to_string(), "36");
    }
    for (key, label) in [
        ("peerCount", "servants"),
        ("grantCount", "masterGrants"),
        ("toolCount", "tools"),
    ] {
        if let Some(value) = event[key].as_u64() {
            field(label, &value.to_string(), "34");
        }
    }
    if let Some(value) = event["elapsedMs"].as_u64() {
        field("duration", &format!("{value}ms"), "33");
    }
    if let Some(code) = event["exitCode"].as_i64() {
        field(
            "exit",
            &code.to_string(),
            if code == 0 { "32" } else { "31" },
        );
    }
    for (key, label) in [
        ("outcomeUnknown", "outcome unknown; verification required"),
        ("replayed", "saved result returned"),
        ("background", "background task"),
    ] {
        if event[key].as_bool() == Some(true) {
            line.push(' ');
            line.push_str(&styled(label, "33", color));
        }
    }
    if let Some(code) = event["errorCode"].as_str() {
        line.push_str(" error=");
        line.push_str(&styled(
            &format!(
                "{code} ({})",
                event["errorDescription"]
                    .as_str()
                    .unwrap_or("Operation failed")
            ),
            "31",
            color,
        ));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn root_error_codes_and_operator_failure_are_visible() {
        let line = format_event(&json!({"event":"task_finished","code":"TOOL_DENIED"}));
        assert!(line.contains("ERROR"));
        assert!(line.contains("TOOL_DENIED (Tool not authorized)"));
        let line = format_event(&json!({"event":"operator_command","ok":false}));
        assert!(line.contains("ERROR"));
        assert!(line.contains("Operator command failed"));
    }

    #[test]
    fn deferred_and_replayed_tasks_do_not_claim_execution() {
        for (key, expected) in [
            ("background", "Task submitted"),
            ("replayed", "Saved result reused"),
        ] {
            let mut event = json!({"event":"task_finished","status":"ok"});
            event[key] = json!(true);
            let line = format_event(&event);
            assert!(line.contains(expected));
            assert!(!line.contains("execution completed"));
        }
    }

    #[test]
    fn text_shortens_ids_while_json_keeps_full_ids() {
        let id = "0123456789ab-cdef-0123-456789abcdef";
        let event =
            json!({"event":"task_started","taskId":id,"requestId":id,"direction":"outgoing"});
        let line = format_event(&event);
        assert!(line.contains("task=0123456789ab…"));
        assert!(line.contains("request=0123456789ab…"));
        assert!(line.contains('→'));
        assert!(!line.contains(id));
        assert!(format_json(&event).contains(id));
    }

    #[test]
    fn registration_and_connection_context_are_readable() {
        assert!(format_event(&json!({"event":"peer_registered"})).contains("Servant registered"));
        let line = format_event(&json!({"event":"master_authorized","toolCount":3}));
        assert!(line.contains("Master authorized"));
        assert!(line.contains("tools=3"));
        let line = format_event(
            &json!({"event":"connection_error","remoteAddr":"100.1.2.3:4","pairingHost":"100.1.2.3","pairingPort":5}),
        );
        assert!(line.contains("remote=100.1.2.3:4"));
        assert!(line.contains("pairing=100.1.2.3:5"));
        let disabled =
            format_event(&json!({"event":"node_ready","pairingHost":"100.1.2.3","pairingPort":0}));
        assert!(disabled.contains("pairing=disabled"));
        assert!(!disabled.contains("pairing=100.1.2.3:0"));
    }

    #[test]
    fn readable_lifecycle_and_time() {
        let line = format_event(
            &json!({"timestamp":0,"nodeId":"cal","event":"node_ready","host":"100.1.2.3","port":18433,"peerCount":2}),
        );
        assert!(line.contains(" INFO [cal] Node ready"));
        assert!(line.contains("listen=100.1.2.3:18433"));
        assert!(line.contains("servants=2"));
        assert_eq!(&line[4..5], "-");
        assert_eq!(&line[19..23], ".000");
        assert!(matches!(&line[23..24], "+" | "-"));
    }

    #[test]
    fn task_success_and_failure() {
        let success = format_event(
            &json!({"event":"task_finished","nodeId":"cal","direction":"outgoing","status":"completed","peerId":"mac","taskId":"t1","tool":"echo","elapsedMs":12}),
        );
        assert!(success.contains("INFO [cal] Remote call completed"));
        assert!(success.contains("peer=mac task=t1 tool=echo"));
        assert!(success.contains("duration=12ms"));
        let failure = format_event(
            &json!({"event":"task_finished","status":"failed","error":{"code":"TLS_ERROR","message":"SECRET"}}),
        );
        assert!(failure.contains("ERROR"));
        assert!(failure.contains("TLS_ERROR (TLS connection failed)"));
        assert!(!failure.contains("SECRET"));
    }

    #[test]
    fn payloads_are_excluded_in_both_formats() {
        let event = json!({"event":"operator_command","nodeId":"cal","command":"dispatch","args":{"token":"SECRET"},"result":"SECRET","text":"SECRET","privateKey":"SECRET","error":{"code":"IO_ERROR","message":"SECRET"}});
        for line in [format_event(&event), format_json(&event)] {
            assert!(!line.contains("SECRET"));
            assert!(!line.contains("privateKey"));
        }
    }

    #[test]
    fn nonzero_exit_and_uncertain_outcome_are_not_success() {
        let line = format_event(
            &json!({"event":"task_finished","status":"ok","exitCode":2,"outcomeUnknown":true}),
        );
        assert!(line.contains("WARN"));
        assert!(line.contains("command exited unsuccessfully"));
        assert!(line.contains("exit=2"));
        assert!(line.contains("outcome unknown; verification required"));
    }

    #[test]
    fn fields_cannot_forge_lines_or_grow_unbounded() {
        let event = json!({"event":"task_started","nodeId":"cal\n\u{1b}[31mFAKE\u{202e}","peerId":"猫".repeat(1000)});
        for line in [format_event(&event), format_json(&event)] {
            assert!(!line.contains('\n'));
            assert!(!line.contains('\u{1b}'));
            assert!(!line.contains('\u{202e}'));
            assert!(line.len() < 1000);
        }
    }

    #[test]
    fn unknown_events_and_formats_are_explicit() {
        assert!(
            format_event(&json!({"event":"unexpected","text":"SECRET"})).contains("Unknown event")
        );
        assert_eq!(LogFormat::parse("text").unwrap(), LogFormat::Text);
        assert_eq!(LogFormat::parse("json").unwrap(), LogFormat::Json);
        assert!(LogFormat::parse("yaml").is_err());
    }
    fn strip_ansi(text: &str) -> String {
        let mut output = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                assert_eq!(chars.next(), Some('['));
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                    assert!(c.is_ascii_digit() || c == ';');
                }
            } else {
                output.push(c);
            }
        }
        output
    }

    #[test]
    fn color_segments_preserve_text_and_sanitize_before_styling() {
        let event = json!({"event":"task_finished","nodeId":"cal\u{1b}[2J","peerId":"mac","taskId":"task1","tool":"echo","elapsedMs":12,"errorCode":"TLS_ERROR"});
        let plain = format_event(&event);
        let colored = format_event_colored(&event, true);
        assert_eq!(strip_ansi(&colored), plain);
        assert_eq!(format_event_colored(&event, false), plain);
        for code in ["90", "31", "36", "34", "35", "33", "1"] {
            assert!(colored.contains(&format!("\u{1b}[{code}m")));
        }
        assert!(!plain.contains('\u{1b}'));
        assert!(!format_json(&event).contains('\u{1b}'));
        assert!(!colored.contains("\u{1b}[2J"));
        assert!(colored.ends_with("\u{1b}[0m"));
    }

    #[test]
    fn color_selection_respects_terminal_and_environment() {
        assert!(use_color(true, false, Some("xterm-256color")));
        assert!(use_color(true, false, None));
        assert!(!use_color(false, false, Some("xterm")));
        assert!(!use_color(true, true, Some("xterm")));
        assert!(!use_color(true, false, Some("dumb")));
    }
}

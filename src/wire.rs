use crate::{IcError, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
pub const MAX_FRAME: usize = 131072;
fn valid(v: &Value, depth: usize) -> bool {
    if depth > 32 && (v.is_array() || v.is_object()) {
        return false;
    }
    match v {
        Value::Array(a) => a.iter().all(|v| valid(v, depth + 1)),
        Value::Object(o) => o.values().all(|v| valid(v, depth + 1)),
        _ => true,
    }
}
pub fn read_frame(reader: &mut impl BufRead) -> Result<Option<Value>> {
    loop {
        let mut bytes = Vec::new();
        loop {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(IcError::new("INVALID_FRAME", "Truncated frame"));
            }
            let take = buffer
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| n + 1)
                .unwrap_or(buffer.len());
            if bytes.len() + take > MAX_FRAME {
                return Err(IcError::new("INVALID_FRAME", "Frame too large"));
            }
            bytes.extend_from_slice(&buffer[..take]);
            reader.consume(take);
            if bytes.last() == Some(&b'\n') {
                break;
            }
            if bytes.len() >= MAX_FRAME {
                return Err(IcError::new("INVALID_FRAME", "Frame too large"));
            }
        }
        if bytes.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        if !v.is_object() || !valid(&v, 1) {
            return Err(IcError::new(
                "INVALID_FRAME",
                "Expected bounded JSON object",
            ));
        }
        return Ok(Some(v));
    }
}
pub fn write_frame(writer: &mut impl Write, value: &Value) -> Result<()> {
    if !value.is_object() || !valid(value, 1) {
        return Err(IcError::new(
            "INVALID_FRAME",
            "Expected bounded JSON object",
        ));
    }
    let mut data = serde_json::to_vec(value)?;
    data.push(b'\n');
    if data.len() > MAX_FRAME {
        return Err(IcError::new("FRAME_TOO_LARGE", "Frame exceeds 128 KiB"));
    }
    writer.write_all(&data)?;
    writer.flush()?;
    Ok(())
}
pub fn fingerprint(task: &Value) -> String {
    let mut t = json!({"tool":task["tool"],"args":task["args"],"timeoutMs":task["timeoutMs"],"runId":task.get("runId").cloned().unwrap_or(json!("default"))});
    if let Some(w) = task.get("workspaceId") {
        t["workspaceId"] = w.clone()
    }
    for key in ["sessionId", "sessionTemporary"] {
        if let Some(value) = task.get(key) {
            t[key] = value.clone();
        }
    }
    hex::encode(Sha256::digest(serde_json::to_vec(&t).unwrap()))
}

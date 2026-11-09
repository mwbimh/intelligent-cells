use intelligent_cells::wire::{fingerprint, read_frame, write_frame};
use serde_json::json;
#[test]
fn frames_are_bounded_objects() {
    assert!(read_frame(&mut &b"[]\n"[..]).is_err());
    assert!(read_frame(&mut &b"{\"x\":\"\xff\"}\n"[..]).is_err());
    assert!(read_frame(&mut &vec![b'x'; 131072][..]).is_err());
    let mut out = Vec::new();
    write_frame(&mut out, &json!({"a":1})).unwrap();
    assert_eq!(read_frame(&mut &out[..]).unwrap(), Some(json!({"a":1})));
}
#[test]
fn task_fingerprint_is_canonical() {
    assert_eq!(
        fingerprint(&json!({"tool":"x","args":{"b":2,"a":1},"taskId":"a"})),
        fingerprint(&json!({"tool":"x","args":{"a":1,"b":2},"taskId":"b"}))
    );
}
#[test]
fn task_fingerprint_isolates_session_workspaces() {
    let task = json!({"tool":"writeFile","args":{},"sessionId":"a","sessionTemporary":true});
    let mut other = task.clone();
    other["sessionId"] = json!("b");
    assert_ne!(fingerprint(&task), fingerprint(&other));
    other = task.clone();
    other["sessionTemporary"] = json!(false);
    assert_ne!(fingerprint(&task), fingerprint(&other));
}
#[test]
fn exactly_32_containers_are_allowed() {
    let mut value = json!(0);
    for _ in 0..31 {
        value = json!([value])
    }
    let root = json!({"nested":value});
    let mut bytes = vec![];
    write_frame(&mut bytes, &root).unwrap();
    assert_eq!(read_frame(&mut &bytes[..]).unwrap(), Some(root));
    let too_deep = json!({"nested":[value]});
    assert!(write_frame(&mut vec![], &too_deep).is_err());
}

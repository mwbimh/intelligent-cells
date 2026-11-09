use intelligent_cells::{Config, owner, wire};
use serde_json::json;
use std::{
    fs,
    io::BufReader,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    thread,
    time::Duration,
};

#[test]
fn session_mcp_response_can_outlive_initial_frame_timeout() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("owner.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let command = wire::read_frame(&mut BufReader::new(stream.try_clone().unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(command["command"], "sessionMcp");
        thread::sleep(Duration::from_millis(11000));
        wire::write_frame(&mut stream, &json!({"ok":true,"result":{"finished":true}}))
    });
    let config = Config {
        raw: json!({}),
        id: "test".into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: directory.path().join("config.json"),
        state_dir: directory.path().to_path_buf(),
    };
    let response = owner::request(
        &config,
        &json!({"command":"sessionMcp","sessionId":"test","request":{"id":1,"method":"tools/call","params":{"name":"ic_wait","arguments":{"timeoutMs":15000}}}}),
    );
    let server_result = server.join().unwrap();
    assert_eq!(response.unwrap()["finished"], true);
    server_result.unwrap();
}

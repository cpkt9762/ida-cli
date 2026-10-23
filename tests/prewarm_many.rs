//! Batch CLI contracts against an isolated, one-request-per-connection daemon.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Output};

struct Case(std::path::PathBuf);
impl Case {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::path::PathBuf::from(format!(
            "/tmp/ib-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("unique short fixture root");
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove batch fixture");
    }
}

fn batch(responses: Vec<Value>) -> Output {
    let case = Case::new();
    let socket_case = Case::new();
    let socket = socket_case.path().join("sock");
    let listener = UnixListener::bind(&socket).expect("bind batch daemon");
    let count = responses.len();
    let daemon = std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().expect("batch connection");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("reader clone"))
                .read_line(&mut line)
                .expect("batch request");
            let request: Value = serde_json::from_str(&line).expect("JSON request");
            let mut response = response;
            response["id"] = request["id"].clone();
            writeln!(stream, "{response}").expect("batch response");
        }
    });
    let list = case.path().join("list");
    std::fs::write(&list, "first\nsecond\n").expect("two batch paths");
    let output = Command::new(env!("CARGO_BIN_EXE_ida-cli"))
        .args([
            "--socket",
            socket.to_str().expect("socket path"),
            "--compact",
            "prewarm-many",
        ])
        .arg(list)
        .args(["--jobs", "1"])
        .env("IDA_CLI_HOME", case.path().join("home"))
        .output()
        .expect("run batch CLI");
    daemon.join().expect("fake daemon stopped");
    assert_eq!(count, 2, "these cases answer both items");
    output
}

#[test]
fn any_failed_item_sets_exit_one_and_preserves_every_result() {
    let success = json!({"jsonrpc":"2.0","id":"", "result":{"cached_after":true}});
    let failure =
        json!({"jsonrpc":"2.0","id":"", "error":{"code":-32000,"message":"test failure"}});
    for responses in [
        vec![failure.clone(), failure.clone()],
        vec![success, failure],
    ] {
        let output = batch(responses);
        assert_eq!(
            output.status.code(),
            Some(1),
            "stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let table: Value = serde_json::from_slice(&output.stdout).expect("complete result table");
        assert_eq!(table["count"], 2);
        assert_eq!(table["results"][0]["path"], "first");
        assert_eq!(table["results"][1]["path"], "second");
        assert_eq!(table["results"][1]["ok"], false);
    }
}

#[test]
fn accepted_queue_items_exit_zero_without_replay() {
    let output = batch(vec![
        json!({"jsonrpc":"2.0","id":"", "result":{"status":"queued","task_id":"one"}}),
        json!({"jsonrpc":"2.0","id":"", "result":{"status":"queued","task_id":"two"}}),
    ]);
    assert!(output.status.success());
    let table: Value = serde_json::from_slice(&output.stdout).expect("queue result table");
    assert_eq!(table["count"], 2);
    assert_eq!(table["results"][1]["result"]["task_id"], "two");
}

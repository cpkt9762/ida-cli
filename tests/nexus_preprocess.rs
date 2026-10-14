use ida_mcp::error::ToolError;
use ida_mcp::preprocess::{self, Preparation, StagedArtifact};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::Command;

struct Fixture {
    directory: PathBuf,
    listener: UnixListener,
    marker: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(1);
        let base = std::env::var_os("TMPDIR").expect("isolated TMPDIR required");
        let directory = PathBuf::from(base).join(format!(
            "n2-proc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("unique fixture directory");
        let listener =
            UnixListener::bind(directory.join("ready.sock")).expect("fixture handshake socket");
        let marker = directory.join("final-marker");
        Self {
            directory,
            listener,
            marker,
        }
    }
    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/n2_process_fixture.py"
            ))
            .arg(mode)
            .arg(self.directory.join("ready.sock"))
            .arg(&self.marker);
        command
    }
    async fn started(&self) -> (BufReader<tokio::net::UnixStream>, serde_json::Value) {
        let (stream, _) = tokio::time::timeout(Duration::from_secs(3), self.listener.accept())
            .await
            .expect("started deadline")
            .expect("started socket");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("started barrier");
        let value: serde_json::Value =
            serde_json::from_str(&line).expect("process identity handshake");
        assert_eq!(value["pid"], value["pgid"], "task-owned group leader");
        use std::io::Write;
        let audit = self
            .directory
            .parent()
            .unwrap()
            .join("n2-process-identities.jsonl");
        let line = format!(
            "{}\n",
            serde_json::to_string(&value).expect("serialize owned process audit")
        );
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit)
            .unwrap()
            .write_all(line.as_bytes())
            .expect("single append of fixture identity");
        (reader, value)
    }
    fn assert_clean(&self, identity: &serde_json::Value) {
        for key in ["pid", "child"] {
            if let Some(pid) = identity[key].as_i64() {
                // SAFETY: non-destructive existence probe of fixture-recorded PIDs only.
                assert_eq!(
                    unsafe { libc::kill(pid as i32, 0) },
                    -1,
                    "owned {key} must be gone"
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
            }
        }
        assert!(
            !self.marker.exists(),
            "cancelled child must not publish delayed final marker"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).expect("fixture cleanup");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn e19_running_cancel_reaps_owned_descendant_and_keeps_router_responsive() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let preparation = Preparation::new(Duration::from_secs(5));
    let cancel = preparation.cancel.clone();
    let running = tokio::spawn(preprocess::run(fixture.command("block"), preparation));
    let (_stream, identity) = fixture.started().await;
    let router = ida_mcp::router::RouterState::new().unwrap();
    tokio::time::timeout(Duration::from_secs(1), router.status_snapshot())
        .await
        .expect("local router status while process blocked");
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(4), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(
            error,
            ToolError::Preparation {
                execution_stopped: true,
                ..
            }
        ),
        "{error}"
    );
    fixture.assert_clean(&identity);
}
#[tokio::test(flavor = "current_thread")]
async fn e19_parent_future_abort_runs_cleanup_before_late_marker() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let preparation = Preparation::new(Duration::from_secs(5));
    let running = tokio::spawn(preprocess::run(fixture.command("block"), preparation));
    let (mut stream, identity) = fixture.started().await;
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    // Socket close is a real process-exit barrier. Supervisor then reaps leader.
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        // SAFETY: non-destructive probe; the supervisor, not this test, reaps.
        if unsafe { libc::kill(identity["pid"].as_i64().unwrap() as i32, 0) } != 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "supervisor must reap after waiter abort"
        );
        tokio::task::yield_now().await;
    }
    fixture.assert_clean(&identity);
}
#[tokio::test(flavor = "current_thread")]
async fn e19_total_deadline_cleans_process_and_drains_saturated_pipes() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let preparation = Preparation::new(Duration::from_secs(1));
    let running = tokio::spawn(preprocess::run(fixture.command("flood"), preparation));
    let (mut stream, identity) = fixture.started().await;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line, "drained\n");
    let error = tokio::time::timeout(Duration::from_secs(4), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(
            error,
            ToolError::Preparation {
                execution_stopped: true,
                ..
            }
        ),
        "{error}"
    );
    fixture.assert_clean(&identity);
}
#[tokio::test(flavor = "current_thread")]
async fn queued_cancel_and_expired_admission_never_spawn() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let preparation = Preparation::new(Duration::from_secs(1));
    preparation.cancel.cancel();
    assert!(preprocess::run(fixture.command("block"), preparation)
        .await
        .is_err());
    let expired = Preparation::new(Duration::ZERO);
    assert!(preprocess::run(fixture.command("block"), expired)
        .await
        .is_err());
    assert!(!fixture.marker.exists());
}
#[tokio::test(flavor = "current_thread")]
async fn staged_publication_preserves_existing_user_output_and_rejects_cancel() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let stage = StagedArtifact::create(&fixture.marker).unwrap();
    std::fs::write(&stage.output, b"new output").unwrap();
    let preparation = Preparation::new(Duration::from_secs(1));
    preparation.cancel.cancel();
    assert!(stage.publish(&preparation).is_err());
    assert!(!fixture.marker.exists());
    let preparation = Preparation::new(Duration::from_secs(1));
    std::fs::write(&fixture.marker, b"user output").unwrap();
    assert!(stage.publish(&preparation).is_err());
    assert_eq!(std::fs::read(&fixture.marker).unwrap(), b"user output");
}
#[tokio::test(flavor = "current_thread")]
async fn successful_disposable_idat_uses_output_and_finite_capture() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let preparation = Preparation::new(Duration::from_secs(3));
    let running = tokio::spawn(preprocess::run(fixture.command("success"), preparation));
    let (mut stream, _identity) = fixture.started().await;
    stream.get_mut().write_all(b"G").await.unwrap();
    let output = running.await.unwrap().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.len() <= 65536);
    assert!(output.stderr.len() <= 65536);
    assert_eq!(std::fs::read(&fixture.marker).unwrap(), b"staged result");
}

static PROCESS_FIXTURE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
#[tokio::test(flavor = "current_thread")]
async fn dsc_production_idat_preserves_arguments_env_and_cancellation_cleanup() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let executable = fixture.directory.join("idat-fixture");
    let stage = StagedArtifact::create(&fixture.marker).unwrap();
    let body=format!("#!/usr/bin/python3\nimport os,sys,runpy\nassert 'IDADIR' not in os.environ and 'DYLD_LIBRARY_PATH' not in os.environ\nassert os.environ['IDA_DYLD_CACHE_MODULE'] == 'fixture-module'\nassert sys.argv[1:5] == ['-a-', '-A', '-P+', '-Oobjc:+l']\noutput=next(a[2:] for a in sys.argv[1:] if a.startswith('-o'))\nsys.argv=[sys.argv[0],'block',{:?},output]\nrunpy.run_path({:?},run_name='__main__')\n",fixture.directory.join("ready.sock").display().to_string(),concat!(env!("CARGO_MANIFEST_DIR"),"/tests/support/n2_process_fixture.py"));
    std::fs::write(&executable, body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let input = fixture.directory.join("dsc-input");
    std::fs::write(&input, b"disposable DSC input").unwrap();
    let args = ida_mcp::dsc::idat_dsc_args(
        &input,
        &stage.output,
        &stage.directory.join("load.py"),
        "fixture-loader",
        None,
    );
    let preparation = Preparation::new(Duration::from_secs(5));
    let cancel = preparation.cancel.clone();
    let running = tokio::spawn(async move {
        ida_mcp::dsc::run_idat_offline(&executable, &args, "fixture-module", preparation).await
    });
    let (_stream, identity) = fixture.started().await;
    assert!(cancel.cancel());
    let error = running.await.unwrap().unwrap_err();
    assert!(
        matches!(
            error,
            ToolError::Preparation {
                execution_stopped: true,
                ..
            }
        ),
        "{error}"
    );
    assert!(
        !stage.output.exists(),
        "cancelled task cannot write staged output after cleanup"
    );
    fixture.assert_clean(&identity);
}
#[test]
fn runtime_exit_emergency_reaper_stops_task_owned_group() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.blocking_lock();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("isolated current-thread runtime");
    let (fixture, mut stream, identity) = runtime.block_on(async {
        let fixture = Fixture::new();
        tokio::spawn(preprocess::run(
            fixture.command("block"),
            Preparation::new(Duration::from_secs(10)),
        ));
        let (stream, identity) = fixture.started().await;
        (
            fixture,
            stream
                .into_inner()
                .into_std()
                .expect("owned exit-barrier socket"),
            identity,
        )
    });
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(4)))
        .unwrap();
    drop(runtime); // Cancels supervisor itself, not merely its requesting future.
    use std::io::Read;
    assert_eq!(stream.read(&mut [0]).expect("closed process barrier"), 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        let gone = ["pid", "child"].into_iter().all(|key| {
            let pid = identity[key].as_i64().expect("owned fixture PID");
            // SAFETY: non-destructive probes of fixture-recorded identities only.
            unsafe {
                libc::kill(pid as i32, 0) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            }
        });
        if gone {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "emergency group cleanup must finish without runtime"
        );
        std::thread::yield_now();
    }
    fixture.assert_clean(&identity);
}
#[tokio::test(flavor = "current_thread")]
async fn accepted_deadline_includes_blocking_input_without_releasing_its_job_early() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let (started_send, started_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let (done_send, done_receive) = tokio::sync::oneshot::channel();
    let preparation = Preparation::new(Duration::from_millis(100));
    let waiting = tokio::spawn(async move {
        preparation
            .wait(ida_mcp::blocking::run(
                ida_mcp::blocking::WorkClass::Prepare,
                move || {
                    started_send.send(()).unwrap();
                    release_receive.recv().unwrap();
                    done_send.send(()).unwrap();
                },
            ))
            .await
    });
    started_receive
        .await
        .expect("blocking input started barrier");
    let error = waiting.await.unwrap().unwrap_err();
    assert!(
        matches!(
            error,
            ToolError::Preparation {
                execution_stopped: false,
                ..
            }
        ),
        "{error}"
    );
    release_send.send(()).unwrap();
    done_receive
        .await
        .expect("retained blocking job completed after explicit release");
}

#[tokio::test(flavor = "current_thread")]
async fn actual_process_queue_cancel_is_not_sent_and_is_bounded() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let mut active = Vec::new();
    for _ in 0..4 {
        let fixture = Fixture::new();
        let preparation = Preparation::new(Duration::from_secs(10));
        let cancel = preparation.cancel.clone();
        let task = tokio::spawn(preprocess::run(fixture.command("block"), preparation));
        let (stream, identity) = fixture.started().await;
        active.push((fixture, cancel, task, stream, identity));
    }
    let queued_fixture = Fixture::new();
    let preparation = Preparation::new(Duration::from_secs(5));
    let cancel = preparation.cancel.clone();
    let queued = tokio::spawn(preprocess::run(
        queued_fixture.command("block"),
        preparation,
    ));
    tokio::task::yield_now().await;
    assert!(!queued.is_finished());
    assert!(cancel.cancel());
    let error = queued.await.unwrap().unwrap_err();
    assert!(matches!(
        error,
        ToolError::Preparation {
            execution_stopped: true,
            ..
        }
    ));
    assert!(!queued_fixture.marker.exists());
    for (fixture, cancel, task, _stream, identity) in active {
        assert!(cancel.cancel());
        let error = task.await.unwrap().unwrap_err();
        assert!(
            matches!(
                error,
                ToolError::Preparation {
                    execution_stopped: true,
                    ..
                }
            ),
            "{error}"
        );
        fixture.assert_clean(&identity);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sbx_production_entry_cancellation_never_publishes_final_output() {
    let _fixture_gate = PROCESS_FIXTURE_GATE.lock().await;
    let fixture = Fixture::new();
    let executable = fixture.directory.join("sbx-fixture");
    let input = fixture.directory.join("program.so");
    std::fs::write(&input, b"copied fixture program").unwrap();
    let body=format!("#!/usr/bin/python3\nimport sys,runpy\nassert sys.argv[1:3] == ['aot','i64']\noutput=sys.argv[sys.argv.index('--output')+1]\nsys.argv=[sys.argv[0],'block',{:?},output]\nrunpy.run_path({:?},run_name='__main__')\n",fixture.directory.join("ready.sock").display().to_string(),concat!(env!("CARGO_MANIFEST_DIR"),"/tests/support/n2_process_fixture.py"));
    std::fs::write(&executable, body).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let old_sbx = std::env::var_os("SBX");
    unsafe {
        std::env::set_var("SBX", &executable);
    }
    let preparation = Preparation::new(Duration::from_secs(5));
    let cancel = preparation.cancel.clone();
    let output = fixture.marker.clone();
    let running =
        tokio::spawn(
            async move { ida_mcp::sbpf::run_sbx_aot_i64(&input, &output, preparation).await },
        );
    let (_stream, identity) = fixture.started().await;
    assert!(cancel.cancel());
    let error = running
        .await
        .unwrap()
        .err()
        .expect("sbx cancellation must fail");
    assert!(
        matches!(
            error,
            ToolError::Preparation {
                execution_stopped: true,
                ..
            }
        ),
        "{error}"
    );
    match old_sbx {
        Some(value) => unsafe {
            std::env::set_var("SBX", value);
        },
        None => unsafe {
            std::env::remove_var("SBX");
        },
    }
    fixture.assert_clean(&identity);
}

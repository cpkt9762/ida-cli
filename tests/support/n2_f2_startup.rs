use ida_mcp::preprocess::{self, Preparation};
use std::future::Future;
use std::task::Poll;
use std::time::Duration;
use tokio::process::Command;
#[test]
fn runtime_drop_before_supervisor_first_poll_must_not_leak_all_process_permits() {
    for _ in 0..4 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut launch = Box::pin(preprocess::run(
                Command::new("/usr/bin/true"),
                Preparation::new(Duration::from_secs(5)),
            ));
            let pending = std::future::poll_fn(|cx| {
                Poll::Ready(matches!(launch.as_mut().poll(cx), Poll::Pending))
            })
            .await;
            assert!(
                pending,
                "child spawned; supervisor has not been polled on current-thread runtime"
            );
        });
        drop(runtime);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(preprocess::run(
        Command::new("/usr/bin/true"),
        Preparation::new(Duration::from_secs(1)),
    ));
    eprintln!("fresh process admission after four startup-window runtime drops: {result:?}");
    assert!(
        result.is_ok(),
        "capacity remains exhausted even after owned true processes are reaped"
    );
}

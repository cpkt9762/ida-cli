pub use ida_mcp::{blocking, error, preprocess};
#[path = "support/n2_f1_review_regressions.rs"]
mod review;
#[path = "support/n2_f1_n2_regressions.rs"]
mod root;

static FIXTURE_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

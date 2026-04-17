// Run: cargo build --bin multi_idb_probe && ./target/debug/multi_idb_probe
use idalib::{idb::IDBOpenOptions, IDB};
use std::path::PathBuf;

fn open_raw(src: &str, out: &str) -> Result<IDB, idalib::IDAError> {
    let mut opts = IDBOpenOptions::new();
    opts.auto_analyse(true);
    opts.idb(&PathBuf::from(out)).save(false).open(src)
}

fn main() {
    idalib::init_library();

    // First open — should succeed
    let db1 =
        open_raw("test/fixtures/mini", "/tmp/probe_a.i64").expect("first open should succeed");
    let db1_funcs = db1.function_count();
    println!("db1: {db1_funcs} functions");

    // Second open WITHOUT closing db1 — expect failure or corruption
    match open_raw("test/fixtures/mini2", "/tmp/probe_b.i64") {
        Ok(db2) => {
            let db2_funcs = db2.function_count();
            let db1_after = db1.function_count();
            println!("WARNING: second open succeeded (db2={db2_funcs} funcs)");
            println!("db1 functions after db2 open: {db1_after} (was {db1_funcs})");
            if db1_after != db1_funcs {
                println!("CORRUPTION DETECTED: db1 state changed after db2 open");
            }
        }
        Err(e) => println!("EXPECTED: second open failed: {e}"),
    }
}

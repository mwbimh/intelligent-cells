use intelligent_cells::{Result, harness};
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    harness::cli(std::env::args().skip(1).collect())
}

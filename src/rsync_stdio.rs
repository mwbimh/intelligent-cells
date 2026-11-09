//! Fixed local pipe bridge used by IC's rsync client, never a remote command runner.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = intelligent_cells::rsync::stdio_bridge(&args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

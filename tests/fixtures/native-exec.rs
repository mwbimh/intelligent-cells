use std::{env, fs, io, os::unix::fs::MetadataExt, process};

fn run() -> io::Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 2 || args[1] != "src/main.txt" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: ic-native-fixture metadata|count src/main.txt",
        ));
    }
    let metadata = fs::metadata(&args[1])?;
    match args[0].as_str() {
        "metadata" => println!(
            "{}:{}:{:o}",
            metadata.ino(),
            metadata.mtime(),
            metadata.mode()
        ),
        "count" => println!("{} {}", metadata.len(), args[1]),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown fixture command",
            ));
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

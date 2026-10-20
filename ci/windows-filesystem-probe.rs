use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn report_directory_flush(directory: &Path, write: bool) {
    let result = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(directory);
    match result {
        Ok(file) => println!(
            "directory handle write={write}: opened; sync_all={:?}",
            file.sync_all()
        ),
        Err(error) => println!("directory handle write={write}: open failed: {error:?}"),
    }
}

fn main() -> io::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .expect("probe directory argument");
    let root = Path::new(&root);
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir(&source)?;
    fs::create_dir(&destination)?;
    let mut file = File::create_new(source.join("payload"))?;
    file.write_all(b"narjar native Windows filesystem contract probe")?;
    file.sync_all()?;
    println!("regular file write + sync_all: succeeded");
    fs::rename(source.join("payload"), destination.join("payload"))?;
    file.sync_all()?;
    println!("same-volume rename + open-file sync_all: succeeded");
    report_directory_flush(&source, false);
    report_directory_flush(&source, true);
    report_directory_flush(&destination, false);
    report_directory_flush(&destination, true);
    Ok(())
}

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;

fn report_directory_rename(root: &Path, share_delete: bool, lock_child: bool) -> io::Result<()> {
    let source = root.join(format!("rename-share-delete-{share_delete}-locked-{lock_child}"));
    let moved = source.with_extension("moved");
    fs::create_dir(&source)?;
    let directory = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&source)?;
    let sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
    let child = OpenOptions::new().read(true).write(true).create_new(true)
        .share_mode(sharing).open(source.join("lock"))?;
    if lock_child { child.try_lock().map_err(io::Error::other)?; }
    let result = fs::rename(&source, &moved);
    println!("root rename with child share_delete={share_delete} locked={lock_child}: {result:?}");
    drop(child);
    if result.is_err() {
        println!("root rename after closing child, root handle retained: {:?}", fs::rename(&source, &moved));
    }
    directory.sync_all()?;
    Ok(())
}

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
    for (share_delete, locked) in [(true, false), (true, true), (false, false), (false, true)] {
        report_directory_rename(root, share_delete, locked)?;
    }
    Ok(())
}

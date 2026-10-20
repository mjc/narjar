//! An owning, bounded directory cursor. fs_at::ReadDir borrows its File and
//! cannot be returned with an independently owned cursor without self-borrowing.

use std::{
    ffi::OsString,
    fs::File,
    io, mem,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
};

use windows_sys::Win32::{
    Foundation::ERROR_NO_MORE_FILES,
    Storage::FileSystem::{
        FILE_ID_BOTH_DIR_INFO, FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo,
        GetFileInformationByHandleEx,
    },
};

use super::invalid_data;

#[repr(C, align(8))]
struct Buffer([u8; 16 * 1024]);

enum State {
    Restart,
    NextBatch,
    Entry(usize),
    Finished,
}

pub(super) struct Names {
    directory: File,
    buffer: Box<Buffer>,
    state: State,
}

impl Names {
    pub(super) fn new(directory: File) -> io::Result<Self> {
        let mut names = Self {
            directory,
            buffer: Box::new(Buffer([0; 16 * 1024])),
            state: State::Restart,
        };
        names.fill()?;
        Ok(names)
    }

    fn fill(&mut self) -> io::Result<()> {
        let class = match self.state {
            State::Restart => FileIdBothDirectoryRestartInfo,
            State::NextBatch => FileIdBothDirectoryInfo,
            State::Entry(_) | State::Finished => {
                return Err(invalid_data("invalid directory cursor state"));
            }
        };
        // SAFETY: the independently opened directory remains alive. The
        // initialized buffer is 8-byte aligned and covers the supplied size.
        let result = unsafe {
            GetFileInformationByHandleEx(
                self.directory.as_raw_handle(),
                class,
                self.buffer.0.as_mut_ptr().cast(),
                self.buffer.0.len() as u32,
            )
        };
        if result != 0 {
            self.state = State::Entry(0);
            return Ok(());
        }
        let error = io::Error::last_os_error();
        self.state = State::Finished;
        if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn read_entry(&mut self, offset: usize) -> io::Result<OsString> {
        let header_size = mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
        let bytes = self
            .buffer
            .0
            .get(offset..)
            .ok_or_else(|| invalid_data("directory entry offset exceeds buffer"))?;
        let next = read_u32(
            bytes,
            mem::offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset),
        )? as usize;
        let length = read_u32(
            bytes,
            mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength),
        )? as usize;
        let record_end = if next == 0 { bytes.len() } else { next };
        if record_end > bytes.len() || record_end < header_size || length % 2 != 0 {
            return Err(invalid_data("invalid directory entry layout"));
        }
        let name = bytes
            .get(
                header_size
                    ..header_size
                        .checked_add(length)
                        .ok_or_else(|| invalid_data("directory name length overflow"))?,
            )
            .filter(|_| length <= record_end - header_size)
            .ok_or_else(|| invalid_data("directory name exceeds entry"))?;
        let wide: Vec<u16> = name
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let name = OsString::from_wide(&wide);
        self.state = if next == 0 {
            State::NextBatch
        } else {
            State::Entry(offset + next)
        };
        Ok(name)
    }
}

impl Iterator for Names {
    type Item = io::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.state {
                State::Finished => return None,
                State::Entry(offset) => {
                    let result = self.read_entry(offset);
                    if result.is_err() {
                        self.state = State::Finished;
                    }
                    return Some(result);
                }
                State::Restart | State::NextBatch => {
                    if let Err(error) = self.fill() {
                        return Some(Err(error));
                    }
                }
            }
        }
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let word: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_data("truncated directory entry header"))?
        .try_into()
        .map_err(|_| invalid_data("invalid directory entry word"))?;
    Ok(u32::from_le_bytes(word))
}

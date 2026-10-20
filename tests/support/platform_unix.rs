pub(super) fn configure_server_process(_: &mut std::process::Command) -> std::io::Result<()> {
    Ok(())
}

pub(super) fn request_shutdown(process: u32) -> std::io::Result<()> {
    let process = rustix::process::Pid::from_raw(
        process
            .try_into()
            .map_err(|_| std::io::ErrorKind::InvalidInput)?,
    )
    .ok_or(std::io::ErrorKind::InvalidInput)?;
    rustix::process::kill_process(process, rustix::process::Signal::TERM).map_err(Into::into)
}

pub(super) fn deny_fixture_data_reads(path: &std::path::Path) -> impl Drop {
    use std::os::unix::fs::PermissionsExt;
    let original = std::fs::metadata(path).unwrap().permissions();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    scopeguard::guard((path.to_owned(), original), |(path, permissions)| {
        std::fs::set_permissions(path, permissions).unwrap()
    })
}

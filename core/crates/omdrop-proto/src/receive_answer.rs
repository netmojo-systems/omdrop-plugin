//! Private, one-request-only desktop replies. No files are created by a reply.
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

pub fn directory() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        // SAFETY: getuid cannot fail.
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
    runtime.join("omdrop/receive-requests")
}

pub fn private_directory(path: &Path, create: bool) -> io::Result<()> {
    if create {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: getuid cannot fail. Reject symlinks, other owners and shared dirs.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "receive request directory must be private",
        ));
    }
    Ok(())
}

pub fn socket_path(directory: &Path, token: &str) -> io::Result<PathBuf> {
    if token.len() != 32
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid receive request token",
        ));
    }
    Ok(directory.join(format!("{token}.sock")))
}

pub fn send(directory: &Path, token: &str, answer: &str) -> io::Result<()> {
    if !matches!(answer, "accept" | "decline") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected accept or decline",
        ));
    }
    private_directory(directory, false)?;
    UnixDatagram::unbound()?.send_to(answer.as_bytes(), socket_path(directory, token)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn reply_requires_a_live_private_request_and_valid_token() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("requests");
        private_directory(&directory, true).unwrap();
        let token = "0123456789abcdef0123456789abcdef";
        let path = socket_path(&directory, token).unwrap();
        let socket = UnixDatagram::bind(&path).unwrap();
        send(&directory, token, "accept").unwrap();
        let mut data = [0; 16];
        let n = socket.recv(&mut data).unwrap();
        assert_eq!(&data[..n], b"accept");
        assert!(send(&directory, "../../not-a-token", "accept").is_err());
        assert!(send(&directory, token, "anything").is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(send(&directory, token, "accept").is_err());
        assert!(!path.exists());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(send(&directory, token, "accept").is_err());
    }
}

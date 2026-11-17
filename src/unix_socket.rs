//! Unix sockets at paths longer than `sockaddr_un.sun_path`.
//!
//! `std::os::unix::net` refuses a path that does not fit `sun_path` (103 bytes on macOS). The
//! macOS kernel takes an address up to `SOCK_MAXADDRLEN` (255 bytes), so a longer path gets an
//! address built by hand. A sandboxed app needs this: its container path alone uses most of the
//! 103 bytes.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

/// The longest socket path macOS takes: `SOCK_MAXADDRLEN` less `sun_len`, `sun_family` and the
/// terminator.
pub const MACOS_MAX_PATH: usize = 252;

/// `UnixListener::bind`, for a path up to [`MACOS_MAX_PATH`] on macOS.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    #[cfg(target_os = "macos")]
    if let Some(addr) = long::address(path)? {
        return long::bind(&addr);
    }
    UnixListener::bind(path)
}

/// `UnixStream::connect`, for a path up to [`MACOS_MAX_PATH`] on macOS.
pub fn connect(path: &Path) -> io::Result<UnixStream> {
    #[cfg(target_os = "macos")]
    if let Some(addr) = long::address(path)? {
        return long::connect(&addr);
    }
    UnixStream::connect(path)
}

#[cfg(target_os = "macos")]
mod long {
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    const SUN_PATH_MAX: usize = 103;
    /// `sun_len` and `sun_family` come before the path.
    const PATH_OFFSET: usize = 2;

    pub struct Address {
        bytes: [u8; libc::SOCK_MAXADDRLEN as usize],
        len: libc::socklen_t,
    }

    /// The hand-built address for `path`, or `None` when std's own address takes it.
    pub fn address(path: &Path) -> io::Result<Option<Address>> {
        let path = path.as_os_str().as_bytes();
        if path.len() <= SUN_PATH_MAX {
            return Ok(None);
        }
        if path.len() > super::MACOS_MAX_PATH || path.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket path is longer than macOS takes or contains a NUL byte",
            ));
        }
        let len = PATH_OFFSET + path.len() + 1;
        let mut bytes = [0; libc::SOCK_MAXADDRLEN as usize];
        bytes[0] = len as u8;
        bytes[1] = libc::AF_UNIX as u8;
        bytes[PATH_OFFSET..PATH_OFFSET + path.len()].copy_from_slice(path);
        Ok(Some(Address { bytes, len: len as libc::socklen_t }))
    }

    fn socket() -> io::Result<OwnedFd> {
        // SAFETY: a plain socket(2) call; the OwnedFd takes the new fd.
        let fd: RawFd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh socket that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: `fd` is valid; FD_CLOEXEC matches what std sets on its sockets.
        unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_SETFD, libc::FD_CLOEXEC) };
        Ok(fd)
    }

    fn check(rc: libc::c_int) -> io::Result<()> {
        if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    pub fn bind(addr: &Address) -> io::Result<UnixListener> {
        let fd = socket()?;
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
        // SAFETY: `addr.bytes` holds `addr.len` initialized bytes of a sockaddr_un.
        check(unsafe { libc::bind(raw, addr.bytes.as_ptr().cast(), addr.len) })?;
        // SAFETY: `raw` is a bound stream socket.
        check(unsafe { libc::listen(raw, 128) })?;
        Ok(UnixListener::from(fd))
    }

    pub fn connect(addr: &Address) -> io::Result<UnixStream> {
        let fd = socket()?;
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
        // SAFETY: `addr.bytes` holds `addr.len` initialized bytes of a sockaddr_un.
        check(unsafe { libc::connect(raw, addr.bytes.as_ptr().cast(), addr.len) })?;
        Ok(UnixStream::from(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn a_path_past_sun_path_binds_and_connects() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("d".repeat(120));
        std::fs::create_dir_all(&deep).unwrap();
        let path = deep.join("bridge.sock");
        assert!(path.as_os_str().len() > 103);

        let listener = bind(&path).unwrap();
        let mut client = connect(&path).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"ok").unwrap();
        let mut reply = [0; 2];
        server.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
    }

    #[test]
    fn a_path_past_the_macos_maximum_is_refused() {
        let path = Path::new("/").join("x".repeat(MACOS_MAX_PATH + 1));
        let refused = bind(&path).is_err();
        assert!(refused);
    }
}

//! Socket helpers.
//!
//! When `--bind-interface` is used the socket is created through libc so the
//! interface option can be applied before `connect`. On macOS that is
//! `IP_BOUND_IF` / `IPV6_BOUND_IF`; on Linux it is `SO_BINDTODEVICE`, which
//! requires CAP_NET_RAW (root). Binding is what lets a measurement bypass a
//! TUN adapter installed by a local proxy.

use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::unix::io::FromRawFd;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const IP_BOUND_IF: libc::c_int = 25;
#[cfg(target_os = "macos")]
const IPV6_BOUND_IF: libc::c_int = 125;
#[cfg(target_os = "linux")]
const SO_BINDTODEVICE: libc::c_int = 25;

/// Connect to `address`, optionally pinning egress to `interface`.
pub fn connect(
    address: SocketAddr,
    timeout: Duration,
    interface: Option<&str>,
) -> io::Result<TcpStream> {
    match interface {
        None => TcpStream::connect_timeout(&address, timeout),
        Some(name) => connect_bound(address, timeout, name),
    }
}

fn sockaddr(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: the storage is zero-initialised and large enough for both
    // families; the returned length matches the family written.
    unsafe {
        let mut storage: libc::sockaddr_storage = mem::zeroed();
        match address {
            SocketAddr::V4(v4) => {
                let target =
                    &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in);
                target.sin_family = libc::AF_INET as libc::sa_family_t;
                target.sin_port = v4.port().to_be();
                target.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                (
                    storage,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            SocketAddr::V6(v6) => {
                let target =
                    &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6);
                target.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                target.sin6_port = v6.port().to_be();
                target.sin6_addr = libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                };
                target.sin6_scope_id = v6.scope_id();
                (
                    storage,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn bind_interface(fd: libc::c_int, address: &SocketAddr, name: &str) -> io::Result<()> {
    // SAFETY: if_nametoindex only reads the provided NUL-terminated string.
    let index =
        unsafe { libc::if_nametoindex(std::ffi::CString::new(name).unwrap_or_default().as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name} not found"),
        ));
    }
    let (level, option) = if address.is_ipv4() {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    };
    let value: libc::c_uint = index;
    // SAFETY: fd is a valid socket; the option expects a c_uint interface index.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            &value as *const libc::c_uint as *const libc::c_void,
            mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_interface(fd: libc::c_int, _address: &SocketAddr, name: &str) -> io::Result<()> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    let bytes = c_name.as_bytes_with_nul();
    // SAFETY: fd is a valid socket; SO_BINDTODEVICE expects a NUL-terminated
    // interface name and is permitted only with CAP_NET_RAW.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BINDTODEVICE,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::PermissionDenied {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("binding to {name} requires root on Linux (CAP_NET_RAW)"),
            ));
        }
        return Err(error);
    }
    Ok(())
}

fn connect_bound(address: SocketAddr, timeout: Duration, name: &str) -> io::Result<TcpStream> {
    let domain = if address.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // The deadline is anchored before socket creation so the whole operation,
    // not just the poll call, is bounded by `timeout`.
    let deadline = Instant::now() + timeout;
    // SAFETY: plain socket creation; the descriptor is closed on every error
    // path below and owned by TcpStream on success.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| -> io::Result<()> {
        bind_interface(fd, &address, name)?;

        // A non-blocking connect plus poll gives a hard, reliable timeout.
        // SO_SNDTIMEO does not bound connect() on macOS, so it is not used.
        // SAFETY: fcntl only inspects and updates flags on our own socket.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: same descriptor, setting O_NONBLOCK.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let (storage, length) = sockaddr(address);
        // SAFETY: storage/length describe a valid sockaddr for this family.
        let rc = unsafe {
            libc::connect(
                fd,
                &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
                length,
            )
        };
        if rc != 0 {
            let error = io::Error::last_os_error();
            // EINTR leaves the connect in an indeterminate state on Linux, and
            // the socket must be polled like an in-progress connect.
            let in_progress = matches!(
                error.raw_os_error(),
                Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EINTR)
            );
            if !in_progress {
                return Err(error);
            }
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
                let mut descriptor = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let millis = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
                // SAFETY: one pollfd is provided and the timeout is bounded.
                let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
                if ready == 0 {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                break;
            }
            let mut so_error: libc::c_int = 0;
            let mut size = mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: reading SO_ERROR into a correctly sized c_int.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut so_error as *mut libc::c_int as *mut libc::c_void,
                    &mut size,
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            if so_error != 0 {
                return Err(io::Error::from_raw_os_error(so_error));
            }
        }
        // SAFETY: restore blocking mode for the TLS handshake.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        Ok(())
    })();

    match result {
        Ok(()) => {
            // SAFETY: fd is a connected stream socket that we own.
            Ok(unsafe { TcpStream::from_raw_fd(fd) })
        }
        Err(error) => {
            // SAFETY: fd is still owned here because it was never wrapped.
            unsafe { libc::close(fd) };
            Err(error)
        }
    }
}

/// True when the address cannot represent a public internet path.
pub fn is_private_path(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || (address.octets()[0] == 198 && matches!(address.octets()[1], 18 | 19))
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
        }
    }
}

/// Classification of an address, used to decide how much a measurement can say
/// about the public internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScope {
    Public,
    /// RFC 1918 / RFC 4193 private space.
    Private,
    /// RFC 6598 carrier-grade NAT space (100.64.0.0/10).
    Shared,
    Loopback,
    LinkLocal,
    /// 198.18.0.0/15, the range commonly used by local proxies for Fake-IP.
    Benchmark,
    /// Documentation ranges such as 192.0.2.0/24 and 2001:db8::/32.
    Documentation,
    Unspecified,
}

impl AddressScope {
    /// Whether the address can represent a public internet destination.
    pub fn is_public(self) -> bool {
        matches!(self, AddressScope::Public)
    }

    pub fn label(self) -> &'static str {
        match self {
            AddressScope::Public => "public",
            AddressScope::Private => "private",
            AddressScope::Shared => "shared_cgnat",
            AddressScope::Loopback => "loopback",
            AddressScope::LinkLocal => "link_local",
            AddressScope::Benchmark => "benchmark_fake_ip",
            AddressScope::Documentation => "documentation",
            AddressScope::Unspecified => "unspecified",
        }
    }
}

/// Classify an address. The benchmark range is reported separately because it
/// is the usual Fake-IP pool, not because it proves anything by itself.
pub fn scope_of(ip: IpAddr) -> AddressScope {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            if address.is_unspecified() {
                AddressScope::Unspecified
            } else if address.is_loopback() {
                AddressScope::Loopback
            } else if address.is_link_local() {
                AddressScope::LinkLocal
            } else if octets[0] == 198 && matches!(octets[1], 18 | 19) {
                AddressScope::Benchmark
            } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                AddressScope::Shared
            } else if address.is_private() {
                AddressScope::Private
            } else if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                AddressScope::Documentation
            } else {
                AddressScope::Public
            }
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            if address.is_unspecified() {
                AddressScope::Unspecified
            } else if address.is_loopback() {
                AddressScope::Loopback
            } else if address.is_unicast_link_local() {
                AddressScope::LinkLocal
            } else if address.is_unique_local() {
                AddressScope::Private
            } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                AddressScope::Documentation
            } else {
                AddressScope::Public
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_private_paths() {
        assert!(is_private_path("127.0.0.1".parse().unwrap()));
        assert!(is_private_path("198.18.0.7".parse().unwrap()));
        assert!(is_private_path("fe80::1".parse().unwrap()));
        assert!(!is_private_path("1.1.1.1".parse().unwrap()));
        assert!(!is_private_path("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn scopes_are_distinct() {
        let cases = [
            ("1.1.1.1", AddressScope::Public),
            ("192.168.1.1", AddressScope::Private),
            ("10.1.2.3", AddressScope::Private),
            ("100.64.0.1", AddressScope::Shared),
            ("127.0.0.1", AddressScope::Loopback),
            ("169.254.1.1", AddressScope::LinkLocal),
            ("198.18.0.53", AddressScope::Benchmark),
            ("198.19.255.1", AddressScope::Benchmark),
            ("192.0.2.10", AddressScope::Documentation),
            ("0.0.0.0", AddressScope::Unspecified),
            ("fe80::1", AddressScope::LinkLocal),
            ("fd00::1", AddressScope::Private),
            ("2001:db8::1", AddressScope::Documentation),
            ("2606:4700::1111", AddressScope::Public),
        ];
        for (text, expected) in cases {
            let ip: std::net::IpAddr = text.parse().unwrap();
            assert_eq!(scope_of(ip), expected, "address {text}");
        }
    }

    #[test]
    fn only_public_counts_as_internet_path() {
        assert!(scope_of("8.8.8.8".parse().unwrap()).is_public());
        assert!(!scope_of("192.168.1.1".parse().unwrap()).is_public());
        assert!(!scope_of("198.18.0.1".parse().unwrap()).is_public());
    }

    #[test]
    fn bound_connect_to_loopback_works() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = std::thread::spawn(move || {
            let _ = listener.accept();
        });
        let result = connect(
            SocketAddr::new("127.0.0.1".parse().unwrap(), port),
            Duration::from_secs(2),
            Some("lo0"),
        );
        let _ = accept.join();
        // lo0 exists on macOS; on Linux the equivalent is lo. Accept either.
        if result.is_err() {
            let retry = connect(
                SocketAddr::new("127.0.0.1".parse().unwrap(), port),
                Duration::from_secs(2),
                Some("lo"),
            );
            assert!(retry.is_ok(), "bound loopback connect failed");
        }
    }
}

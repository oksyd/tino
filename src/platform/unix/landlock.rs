use std::ffi::{CStr, CString};

use super::sys::Errno;

pub(super) struct LandlockConfig {
    pub write_requested: bool,
    pub warn_only: bool,
    pub no_dev: bool,
    pub preset_names: Vec<&'static str>,
    pub writable_dirs: Vec<CString>,
    pub bind_tcp_ports: Vec<u16>,
    pub connect_tcp_ports: Vec<u16>,
    pub scope_signals: bool,
    pub scope_abstract_unix: bool,
    pub exec_allow_paths: Vec<CString>,
    pub device_ioctl_allow_paths: Vec<CString>,
}

#[derive(Debug)]
pub(super) enum LandlockError<'a> {
    NotSupported,
    AbiTooOld {
        feature: &'static str,
        required_abi: u32,
        current_abi: u32,
    },
    QueryAbi(Errno),
    CreateRuleset(Errno),
    OpenPath {
        path: &'a CStr,
        errno: Errno,
    },
    AddRule {
        path: &'a CStr,
        errno: Errno,
    },
    AddNetPortRule {
        port: u16,
        action: &'static str,
        errno: Errno,
    },
    SetNoNewPrivs(Errno),
    RestrictSelf(Errno),
}

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 2;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 16;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 32;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 64;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 128;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 256;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 512;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1024;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 2048;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 4096;
const LANDLOCK_ACCESS_FS_REFER: u64 = 8192;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 16384;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 32768;
const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 2;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1;
const LANDLOCK_SCOPE_SIGNAL: u64 = 2;

#[repr(C)]
struct LandlockRulesetAttrV1 {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockRulesetAttrV4 {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockRulesetAttrV6 {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct LandlockNetPortAttr {
    allowed_access: u64,
    port: u64,
}

struct OwnedFd(i32);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        // SAFETY: the file descriptor is owned by this wrapper and must be closed exactly once.
        unsafe {
            libc::close(self.0);
        }
    }
}

pub(super) fn apply(config: &LandlockConfig) -> Result<u32, LandlockError<'_>> {
    let abi_version = match query_abi_version() {
        Ok(Some(version)) => version,
        Ok(None) => return Err(LandlockError::NotSupported),
        Err(errno) => return Err(LandlockError::QueryAbi(errno)),
    };

    let handled_writes = handled_write_access_fs(abi_version, config.write_requested)?;
    let handled_access_fs = handled_writes
        | handled_execute_access(!config.exec_allow_paths.is_empty())
        | handled_ioctl_access(abi_version, !config.device_ioctl_allow_paths.is_empty())?;
    let handled_access_net = handled_network_access(
        abi_version,
        !config.bind_tcp_ports.is_empty(),
        !config.connect_tcp_ports.is_empty(),
    )?;
    let scoped_access = handled_scope_access(
        abi_version,
        config.scope_signals,
        config.scope_abstract_unix,
    )?;
    if handled_access_fs == 0 && handled_access_net == 0 && scoped_access == 0 {
        return Err(LandlockError::NotSupported);
    }
    let allowed_writes = allowed_write_access_fs(handled_writes);

    let ruleset_fd = match create_ruleset(
        abi_version,
        handled_access_fs,
        handled_access_net,
        scoped_access,
    ) {
        Ok(fd) => OwnedFd(fd),
        Err(errno) if errno_indicates_not_supported(errno) => {
            return Err(LandlockError::NotSupported);
        }
        Err(errno) => return Err(LandlockError::CreateRuleset(errno)),
    };

    if config.write_requested && !config.no_dev {
        let dev_dir = c"/dev";
        if let Err(err) =
            add_writable_dir_rule(ruleset_fd.0, dev_dir, LANDLOCK_ACCESS_FS_WRITE_FILE)
        {
            match err {
                LandlockError::OpenPath {
                    errno: Errno::ENOENT,
                    ..
                } => {}
                other => return Err(other),
            }
        }
    }

    for dir in &config.writable_dirs {
        add_writable_dir_rule(ruleset_fd.0, dir.as_c_str(), allowed_writes)?;
    }

    for path in &config.exec_allow_paths {
        add_exec_path_rule(ruleset_fd.0, path.as_c_str())?;
    }

    for path in &config.device_ioctl_allow_paths {
        add_device_ioctl_path_rule(ruleset_fd.0, path.as_c_str())?;
    }

    for port in &config.bind_tcp_ports {
        add_net_port_rule(
            ruleset_fd.0,
            *port,
            LANDLOCK_ACCESS_NET_BIND_TCP,
            "bind TCP",
        )?;
    }

    for port in &config.connect_tcp_ports {
        add_net_port_rule(
            ruleset_fd.0,
            *port,
            LANDLOCK_ACCESS_NET_CONNECT_TCP,
            "connect TCP",
        )?;
    }

    set_no_new_privs().map_err(LandlockError::SetNoNewPrivs)?;
    match restrict_self(ruleset_fd.0) {
        Ok(()) => {}
        Err(errno) if errno_indicates_not_supported(errno) => {
            return Err(LandlockError::NotSupported);
        }
        Err(errno) => return Err(LandlockError::RestrictSelf(errno)),
    }

    Ok(abi_version)
}

const fn handled_write_access_fs(
    abi_version: u32,
    requested: bool,
) -> Result<u64, LandlockError<'static>> {
    if !requested {
        return Ok(0);
    }
    if abi_version < 3 {
        return Err(LandlockError::AbiTooOld {
            feature: "filesystem write restrictions",
            required_abi: 3,
            current_abi: abi_version,
        });
    }
    Ok(LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE)
}

const fn allowed_write_access_fs(handled_writes: u64) -> u64 {
    handled_writes & !(LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK)
}

const fn handled_execute_access(requested: bool) -> u64 {
    if requested {
        LANDLOCK_ACCESS_FS_EXECUTE
    } else {
        0
    }
}

const fn handled_ioctl_access(
    abi_version: u32,
    requested: bool,
) -> Result<u64, LandlockError<'static>> {
    if !requested {
        return Ok(0);
    }
    if abi_version < 5 {
        return Err(LandlockError::AbiTooOld {
            feature: "device ioctl restrictions",
            required_abi: 5,
            current_abi: abi_version,
        });
    }
    Ok(LANDLOCK_ACCESS_FS_IOCTL_DEV)
}

const fn handled_network_access(
    abi_version: u32,
    allow_bind_tcp: bool,
    allow_connect_tcp: bool,
) -> Result<u64, LandlockError<'static>> {
    if !allow_bind_tcp && !allow_connect_tcp {
        return Ok(0);
    }
    if abi_version < 4 {
        return Err(LandlockError::AbiTooOld {
            feature: "TCP port restrictions",
            required_abi: 4,
            current_abi: abi_version,
        });
    }

    let mut handled = 0;
    if allow_bind_tcp {
        handled |= LANDLOCK_ACCESS_NET_BIND_TCP;
    }
    if allow_connect_tcp {
        handled |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }
    Ok(handled)
}

const fn handled_scope_access(
    abi_version: u32,
    scope_signals: bool,
    scope_abstract_unix: bool,
) -> Result<u64, LandlockError<'static>> {
    if !scope_signals && !scope_abstract_unix {
        return Ok(0);
    }
    if abi_version < 6 {
        return Err(LandlockError::AbiTooOld {
            feature: "IPC scopes",
            required_abi: 6,
            current_abi: abi_version,
        });
    }

    let mut handled = 0;
    if scope_abstract_unix {
        handled |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
    }
    if scope_signals {
        handled |= LANDLOCK_SCOPE_SIGNAL;
    }
    Ok(handled)
}

fn query_abi_version() -> std::result::Result<Option<u32>, Errno> {
    // SAFETY: calling a raw syscall with documented parameters and a null pointer for the
    // version query is safe.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret == -1 {
        let errno = Errno::last();
        if errno_indicates_not_supported(errno) {
            Ok(None)
        } else {
            Err(errno)
        }
    } else {
        u32::try_from(ret).map(Some).map_err(|_| Errno::EINVAL)
    }
}

fn create_ruleset(
    abi_version: u32,
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
) -> std::result::Result<i32, Errno> {
    let ret = if abi_version >= 6 {
        let attr = LandlockRulesetAttrV6 {
            handled_access_fs,
            handled_access_net,
            scoped,
        };
        // SAFETY: calling the Landlock create_ruleset syscall with a pointer to a C-compatible
        // struct matching the supported ABI.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &raw const attr,
                std::mem::size_of::<LandlockRulesetAttrV6>(),
                0u32,
            )
        }
    } else if abi_version >= 4 {
        let attr = LandlockRulesetAttrV4 {
            handled_access_fs,
            handled_access_net,
        };
        // SAFETY: calling the Landlock create_ruleset syscall with a pointer to a C-compatible
        // struct matching the supported ABI.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &raw const attr,
                std::mem::size_of::<LandlockRulesetAttrV4>(),
                0u32,
            )
        }
    } else {
        let attr = LandlockRulesetAttrV1 { handled_access_fs };
        // SAFETY: calling the Landlock create_ruleset syscall with a pointer to a C-compatible
        // struct matching the supported ABI.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &raw const attr,
                std::mem::size_of::<LandlockRulesetAttrV1>(),
                0u32,
            )
        }
    };
    if ret == -1 {
        Err(Errno::last())
    } else {
        i32::try_from(ret).map_err(|_| Errno::EINVAL)
    }
}

fn add_writable_dir_rule(
    ruleset_fd: i32,
    path: &CStr,
    allowed_access: u64,
) -> Result<(), LandlockError<'_>> {
    add_path_beneath_rule(ruleset_fd, path, allowed_access, PathRuleKind::Directory)
}

fn add_exec_path_rule(ruleset_fd: i32, path: &CStr) -> Result<(), LandlockError<'_>> {
    add_path_beneath_rule(
        ruleset_fd,
        path,
        LANDLOCK_ACCESS_FS_EXECUTE,
        PathRuleKind::Any,
    )
}

fn add_device_ioctl_path_rule(ruleset_fd: i32, path: &CStr) -> Result<(), LandlockError<'_>> {
    add_path_beneath_rule(
        ruleset_fd,
        path,
        LANDLOCK_ACCESS_FS_IOCTL_DEV,
        PathRuleKind::Any,
    )
}

#[derive(Clone, Copy)]
enum PathRuleKind {
    Any,
    Directory,
}

fn add_path_beneath_rule(
    ruleset_fd: i32,
    path: &CStr,
    allowed_access: u64,
    kind: PathRuleKind,
) -> Result<(), LandlockError<'_>> {
    let path_fd =
        open_rule_path(path, kind).map_err(|errno| LandlockError::OpenPath { path, errno })?;
    let path_fd = OwnedFd(path_fd);
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: path_fd.0,
    };
    // SAFETY: calling the Landlock add_rule syscall with a pointer to a C-compatible struct.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const attr,
            0u32,
        )
    };
    if ret == -1 {
        return Err(LandlockError::AddRule {
            path,
            errno: Errno::last(),
        });
    }
    Ok(())
}

fn add_net_port_rule(
    ruleset_fd: i32,
    port: u16,
    allowed_access: u64,
    action: &'static str,
) -> Result<(), LandlockError<'static>> {
    let attr = LandlockNetPortAttr {
        allowed_access,
        port: u64::from(port),
    };
    // SAFETY: calling the Landlock add_rule syscall with a pointer to a C-compatible struct.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_NET_PORT,
            &raw const attr,
            0u32,
        )
    };
    if ret == -1 {
        return Err(LandlockError::AddNetPortRule {
            port,
            action,
            errno: Errno::last(),
        });
    }
    Ok(())
}

fn open_rule_path(path: &CStr, kind: PathRuleKind) -> std::result::Result<i32, Errno> {
    let extra_flags = match kind {
        PathRuleKind::Any => 0,
        PathRuleKind::Directory => libc::O_DIRECTORY,
    };
    open_path_with_flags(path, extra_flags)
}

fn open_path_with_flags(path: &CStr, extra_flags: libc::c_int) -> std::result::Result<i32, Errno> {
    let flags = libc::O_PATH | libc::O_CLOEXEC | extra_flags;
    // SAFETY: `path` is NUL-terminated and the libc `open` flags are passed as documented.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd == -1 { Err(Errno::last()) } else { Ok(fd) }
}

fn set_no_new_privs() -> std::result::Result<(), Errno> {
    // SAFETY: `prctl` is invoked with documented constants to enable `no_new_privs`.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret == -1 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn restrict_self(ruleset_fd: i32) -> std::result::Result<(), Errno> {
    // SAFETY: calling the Landlock restrict_self syscall with a valid ruleset file descriptor.
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    if ret == -1 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn errno_indicates_not_supported(errno: Errno) -> bool {
    errno == Errno::ENOSYS || errno == Errno::EOPNOTSUPP
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn allowed_write_mask_excludes_device_nodes() {
        let allowed = allowed_write_access_fs(handled_write_access_fs(3, true).unwrap());
        assert_eq!(allowed & LANDLOCK_ACCESS_FS_MAKE_CHAR, 0);
        assert_eq!(allowed & LANDLOCK_ACCESS_FS_MAKE_BLOCK, 0);
        assert_ne!(allowed & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    }

    #[test]
    fn write_restrictions_require_truncation_support() {
        for abi in [1, 2] {
            assert!(matches!(
                handled_write_access_fs(abi, true),
                Err(LandlockError::AbiTooOld {
                    feature: "filesystem write restrictions",
                    required_abi: 3,
                    current_abi,
                }) if current_abi == abi
            ));
            assert_eq!(handled_write_access_fs(abi, false).unwrap(), 0);
        }
        let v3 = handled_write_access_fs(3, true).unwrap();
        assert_ne!(v3 & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_ne!(v3 & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
    }

    #[test]
    fn handled_network_access_requires_abi_v4() {
        let err = handled_network_access(3, true, false).unwrap_err();
        assert!(matches!(
            err,
            LandlockError::AbiTooOld {
                feature: "TCP port restrictions",
                required_abi: 4,
                current_abi: 3,
            }
        ));
    }

    #[test]
    fn handled_network_access_tracks_requested_port_actions() {
        assert_eq!(handled_network_access(4, false, false).unwrap(), 0);
        assert_eq!(
            handled_network_access(4, true, false).unwrap(),
            LANDLOCK_ACCESS_NET_BIND_TCP
        );
        assert_eq!(
            handled_network_access(4, false, true).unwrap(),
            LANDLOCK_ACCESS_NET_CONNECT_TCP
        );
        assert_eq!(
            handled_network_access(4, true, true).unwrap(),
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        );
    }

    #[test]
    fn handled_scope_access_requires_abi_v6() {
        let err = handled_scope_access(5, true, false).unwrap_err();
        assert!(matches!(
            err,
            LandlockError::AbiTooOld {
                feature: "IPC scopes",
                required_abi: 6,
                current_abi: 5,
            }
        ));
    }

    #[test]
    fn handled_scope_access_tracks_requested_scopes() {
        assert_eq!(handled_scope_access(6, false, false).unwrap(), 0);
        assert_eq!(
            handled_scope_access(6, true, false).unwrap(),
            LANDLOCK_SCOPE_SIGNAL
        );
        assert_eq!(
            handled_scope_access(6, false, true).unwrap(),
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
        );
        assert_eq!(
            handled_scope_access(6, true, true).unwrap(),
            LANDLOCK_SCOPE_SIGNAL | LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
        );
    }

    #[test]
    fn handled_ioctl_access_requires_abi_v5() {
        let err = handled_ioctl_access(4, true).unwrap_err();
        assert!(matches!(
            err,
            LandlockError::AbiTooOld {
                feature: "device ioctl restrictions",
                required_abi: 5,
                current_abi: 4,
            }
        ));
    }

    #[test]
    fn handled_execute_and_ioctl_access_track_requested_state() {
        assert_eq!(handled_execute_access(false), 0);
        assert_eq!(handled_execute_access(true), LANDLOCK_ACCESS_FS_EXECUTE);
        assert_eq!(handled_ioctl_access(5, false).unwrap(), 0);
        assert_eq!(
            handled_ioctl_access(5, true).unwrap(),
            LANDLOCK_ACCESS_FS_IOCTL_DEV
        );
    }

    #[test]
    fn directory_rule_open_rejects_regular_files() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-landlock-open-dir-{}-{nanos}",
            std::process::id()
        ));
        let dir = root.join("dir");
        let file = root.join("file");
        std::fs::create_dir_all(&dir).expect("create test directory");
        std::fs::write(&file, b"not a directory").expect("write test file");

        let dir_c = CString::new(dir.as_os_str().as_bytes()).expect("directory path CString");
        let file_c = CString::new(file.as_os_str().as_bytes()).expect("file path CString");

        let dir_fd = open_rule_path(dir_c.as_c_str(), PathRuleKind::Directory)
            .expect("directory path should open as directory");
        let _dir_fd = OwnedFd(dir_fd);
        let file_fd = open_rule_path(file_c.as_c_str(), PathRuleKind::Any)
            .expect("regular file should open for non-directory rule");
        let _file_fd = OwnedFd(file_fd);
        let err = open_rule_path(file_c.as_c_str(), PathRuleKind::Directory)
            .expect_err("regular file must not open as directory rule");

        assert_eq!(err, Errno::ENOTDIR);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn errno_not_supported_classifies_known_values() {
        assert!(errno_indicates_not_supported(Errno::ENOSYS));
        assert!(errno_indicates_not_supported(Errno::EOPNOTSUPP));
        assert!(!errno_indicates_not_supported(Errno::EPERM));
    }
}

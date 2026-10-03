use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::OnceLock;

use libproc::bsd_info::BSDInfo;
use libproc::file_info::{ListFDs, PIDFDInfo, PIDFDInfoFlavor, ProcFDType, pidfdinfo};
use libproc::net_info::{ProcFileInfo, SocketFDInfo, SocketInfoKind, VInfoStat};
use libproc::pid_rusage::{RUsageInfoV2, pidrusage};
use libproc::proc_pid::{listpidinfo, pidinfo};
use libproc::processes::{self, ProcFilter};
use libproc::task_info::TaskInfo;

use crate::formatting::sanitize_process_text;
use crate::network::SocketRecord;
use crate::observation::{
    FileDescriptor, FileDescriptorSnapshot, NetworkSnapshot, ObservationBoundary, ProcessInfo,
    ProcessSnapshot,
};

const FREAD: u32 = 0x1;
const FWRITE: u32 = 0x2;
const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const MAX_FDS: usize = 4096;

// Apple libproc.h calls these interfaces private. Keep their ABI assumptions here.
#[repr(C)]
#[derive(Default)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}

#[repr(C)]
struct VnodeInfoPath {
    stat: VInfoStat,
    vnode_type: i32,
    pad: i32,
    fsid: [i32; 2],
    path: [c_char; 1024],
}

impl Default for VnodeInfoPath {
    fn default() -> Self {
        Self {
            stat: VInfoStat::default(),
            vnode_type: 0,
            pad: 0,
            fsid: [0; 2],
            path: [0; 1024],
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct VnodeFdInfoWithPath {
    file: ProcFileInfo,
    vnode: VnodeInfoPath,
}

impl PIDFDInfo for VnodeFdInfoWithPath {
    fn flavor() -> PIDFDInfoFlavor {
        PIDFDInfoFlavor::VNodePathInfo
    }
}

// XNU sys/proc_info.h: proc_fileinfo + vnode_info + MAXPATHLEN.
const _: [(); 24] = [(); size_of::<ProcFileInfo>()];
const _: [(); 152] = [(); offset_of!(VnodeInfoPath, path)];
const _: [(); 1200] = [(); size_of::<VnodeFdInfoWithPath>()];

pub(crate) struct MacOsObservationBoundary;

impl ObservationBoundary for MacOsObservationBoundary {
    fn process_snapshot(&self, root_pid: u32, known_pids: &[u32]) -> ProcessSnapshot {
        let mut processes = HashMap::new();
        let mut unreadable_pids = HashSet::new();
        let mut seen = HashSet::new();
        let mut pending = vec![root_pid];
        pending.extend_from_slice(known_pids);

        while let Some(pid) = pending.pop() {
            if !seen.insert(pid) {
                continue;
            }
            let Some(info) = read_process_info(pid) else {
                // ESRCH means the process exited between discovery and inspection.
                if process_still_exists(pid) {
                    unreadable_pids.insert(pid);
                }
                continue;
            };
            if pid != root_pid && !known_pids.contains(&pid) && !seen.contains(&info.parent_pid) {
                // Child was reparented before its first snapshot.
                continue;
            }
            processes.insert(pid, info);

            // `proc_listpids` returns zero for no children; libproc checks errno to
            // distinguish that from failure, so clear stale thread-local errno first.
            unsafe { *libc::__error() = 0 };
            match processes::pids_by_type(ProcFilter::ByParentProcess { ppid: pid }) {
                Ok(children) => {
                    pending.extend(children.into_iter().filter(|child| *child != 0));
                }
                Err(_) if process_still_exists(pid) => {
                    unreadable_pids.insert(pid);
                }
                Err(_) => {}
            }
        }

        ProcessSnapshot {
            processes,
            available: true,
            unreadable_pids,
        }
    }

    fn file_descriptors(&self, pid: u32) -> Option<FileDescriptorSnapshot> {
        let (fds, mut limited) = list_fds(pid)?;
        let mut descriptors = Vec::new();
        for fd in fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::VNode) {
                continue;
            }
            let Ok(info) = pidfdinfo::<VnodeFdInfoWithPath>(pid as i32, fd.proc_fd) else {
                limited = true;
                continue;
            };
            let Some(length) = info.vnode.path.iter().position(|byte| *byte == 0) else {
                limited = true;
                continue;
            };
            let bytes = info.vnode.path[..length]
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>();
            if bytes.is_empty() {
                limited = true;
                continue;
            }
            descriptors.push(FileDescriptor {
                path: PathBuf::from(OsString::from_vec(bytes)),
                directory: info.vnode.stat.vst_mode & S_IFMT == S_IFDIR,
                read: info.file.fi_openflags & FREAD != 0,
                write: info.file.fi_openflags & FWRITE != 0,
            });
        }
        Some(FileDescriptorSnapshot {
            descriptors,
            limited,
        })
    }

    fn network_snapshot(&self, pid: u32) -> Option<NetworkSnapshot> {
        let (fds, mut limited) = list_fds(pid)?;
        let mut socket_ids = HashSet::new();
        let mut sockets = HashMap::new();
        for fd in fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let Ok(info) = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) else {
                limited = true;
                continue;
            };
            let Some(record) = socket_record(&info) else {
                // Unix sockets and other families have no IP endpoints.
                if matches!(info.psi.soi_family, 2 | 30) && matches!(info.psi.soi_protocol, 6 | 17)
                {
                    limited = true;
                }
                continue;
            };
            let id = fd.proc_fd as u64;
            socket_ids.insert(id);
            sockets.insert(id, record);
        }
        Some(NetworkSnapshot {
            socket_ids,
            sockets,
            limited,
        })
    }
}

fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let pid_i32 = i32::try_from(pid).ok()?;
    let bsd = pidinfo::<BSDInfo>(pid_i32, 0).ok()?;
    if bsd.pbi_pid != pid {
        return None;
    }
    let task = pidinfo::<TaskInfo>(pid_i32, 0).ok();
    let usage = pidrusage::<RUsageInfoV2>(pid_i32).ok();
    let timebase = mach_timebase();
    let command_bytes = bsd
        .pbi_comm
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    let command = sanitize_process_text(&String::from_utf8_lossy(&command_bytes));

    Some(ProcessInfo {
        pid,
        parent_pid: bsd.pbi_ppid,
        state: match bsd.pbi_status {
            5 => 'Z', // SZOMB
            4 => 'T', // SSTOP
            3 => 'S', // SSLEEP
            _ => 'R',
        },
        command,
        user_cpu_nanos: task
            .as_ref()
            .and_then(|task| mach_to_nanos(task.pti_total_user, timebase)),
        system_cpu_nanos: task
            .as_ref()
            .and_then(|task| mach_to_nanos(task.pti_total_system, timebase)),
        resident_memory_kib: task.as_ref().map(|task| task.pti_resident_size / 1024),
        read_storage_bytes: usage.as_ref().map(|usage| usage.ri_diskio_bytesread),
        write_storage_bytes: usage.as_ref().map(|usage| usage.ri_diskio_byteswritten),
    })
}

fn process_still_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    (unsafe { kill(pid, 0) }) == 0 || std::io::Error::last_os_error().raw_os_error() != Some(3)
}

fn mach_timebase() -> Option<(u32, u32)> {
    static TIMEBASE: OnceLock<Option<(u32, u32)>> = OnceLock::new();
    *TIMEBASE.get_or_init(|| {
        let mut info = MachTimebaseInfo::default();
        if unsafe { mach_timebase_info(&mut info) } != 0 || info.denom == 0 {
            return None;
        }
        Some((info.numer, info.denom))
    })
}

fn mach_to_nanos(ticks: u64, timebase: Option<(u32, u32)>) -> Option<u64> {
    let (numer, denom) = timebase?;
    u64::try_from(u128::from(ticks) * u128::from(numer) / u128::from(denom)).ok()
}

fn list_fds(pid: u32) -> Option<(Vec<libproc::file_info::ProcFDInfo>, bool)> {
    let pid_i32 = i32::try_from(pid).ok()?;
    let bsd = pidinfo::<BSDInfo>(pid_i32, 0).ok()?;
    if bsd.pbi_nfiles == 0 {
        return Some((Vec::new(), false));
    }
    let requested = (bsd.pbi_nfiles as usize).saturating_add(16).min(MAX_FDS);
    let fds = listpidinfo::<ListFDs>(pid_i32, requested).ok()?;
    let limited = fds.len() == requested || bsd.pbi_nfiles as usize >= MAX_FDS;
    Some((fds, limited))
}

fn socket_record(info: &SocketFDInfo) -> Option<SocketRecord> {
    let (protocol, internet, state) = match SocketInfoKind::from(info.psi.soi_kind) {
        SocketInfoKind::Tcp if info.psi.soi_protocol == 6 => {
            let tcp = unsafe { info.psi.soi_proto.pri_tcp };
            ("TCP", tcp.tcpsi_ini, tcp_state(tcp.tcpsi_state))
        }
        SocketInfoKind::In if info.psi.soi_protocol == 17 => {
            let internet = unsafe { info.psi.soi_proto.pri_in };
            let state = if internet.insi_fport == 0 {
                "UNCONNECTED"
            } else {
                "ESTABLISHED"
            };
            ("UDP", internet, state.to_owned())
        }
        _ => return None,
    };
    // INI_IPV4/INI_IPV6 identify stored address shape, including dual-stack sockets.
    let family = if internet.insi_vflag == 1 {
        2
    } else {
        info.psi.soi_family
    };
    let (local_ip, remote_ip) = match family {
        2 => {
            let local = unsafe { internet.insi_laddr.ina_46.i46a_addr4.s_addr };
            let remote = unsafe { internet.insi_faddr.ina_46.i46a_addr4.s_addr };
            (
                IpAddr::V4(Ipv4Addr::from(local.to_ne_bytes())),
                IpAddr::V4(Ipv4Addr::from(remote.to_ne_bytes())),
            )
        }
        30 => {
            let local = unsafe { internet.insi_laddr.ina_6.s6_addr };
            let remote = unsafe { internet.insi_faddr.ina_6.s6_addr };
            (
                IpAddr::V6(Ipv6Addr::from(local)),
                IpAddr::V6(Ipv6Addr::from(remote)),
            )
        }
        _ => return None,
    };
    let local = SocketAddr::new(local_ip, u16::from_be(internet.insi_lport as u16));
    let remote = SocketAddr::new(remote_ip, u16::from_be(internet.insi_fport as u16));
    SocketRecord::from_socket_addrs(protocol, local, remote, state)
}

fn tcp_state(state: i32) -> String {
    match state {
        0 => "CLOSE",
        1 => "LISTEN",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "ESTABLISHED",
        5 => "CLOSE_WAIT",
        6 => "FIN_WAIT1",
        7 => "CLOSING",
        8 => "LAST_ACK",
        9 => "FIN_WAIT2",
        10 => "TIME_WAIT",
        _ => return format!("0x{state:02X}"),
    }
    .to_owned()
}

use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(target_os = "linux")]
use std::os::raw::{c_int, c_long};
use std::path::{Path, PathBuf};

use crate::formatting::sanitize_process_text;
use crate::network::{read_network_sockets, read_socket_inodes};
use crate::observation::{
    FileDescriptor, FileDescriptorSnapshot, LinuxObservationBoundary, NetworkSnapshot,
    ObservationBoundary, ProcessInfo, ProcessSnapshot,
};

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn sysconf(name: c_int) -> c_long;
}

#[cfg(target_os = "linux")]
const SC_CLK_TCK: c_int = 2;

fn read_fd_access(fd_path: &Path) -> Option<(bool, bool)> {
    let fd = fd_path.file_name()?.to_str()?;
    let process_directory = fd_path.parent()?.parent()?;
    let fdinfo = fs::read_to_string(process_directory.join("fdinfo").join(fd)).ok()?;
    let flags = fdinfo.lines().find_map(|line| {
        let value = line.strip_prefix("flags:")?.trim();
        u32::from_str_radix(value, 8).ok()
    })?;

    match flags & 0o3 {
        0 => Some((true, false)),
        1 => Some((false, true)),
        2 => Some((true, true)),
        _ => None,
    }
}

fn path_without_deleted_suffix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    text.strip_suffix(" (deleted)")
        .map(PathBuf::from)
        .unwrap_or_else(|| path.to_path_buf())
}

impl ObservationBoundary for LinuxObservationBoundary {
    fn process_snapshot(&self) -> ProcessSnapshot {
        current_processes()
    }

    fn file_descriptors(&self, pid: u32) -> Option<FileDescriptorSnapshot> {
        let entries = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        let mut descriptors = Vec::new();
        let mut limited = false;
        for entry in entries {
            let Ok(entry) = entry else {
                limited = true;
                continue;
            };
            let fd_path = entry.path();
            let Ok(target) = fs::read_link(&fd_path) else {
                limited = true;
                continue;
            };
            let Ok(metadata) = fs::metadata(&fd_path) else {
                limited = true;
                continue;
            };
            if !metadata.file_type().is_file() && !metadata.file_type().is_dir() {
                continue;
            }
            let Some((read, write)) = read_fd_access(&fd_path) else {
                limited = true;
                continue;
            };
            descriptors.push(FileDescriptor {
                path: path_without_deleted_suffix(&target),
                directory: metadata.file_type().is_dir(),
                read,
                write,
            });
        }
        Some(FileDescriptorSnapshot {
            descriptors,
            limited,
        })
    }

    fn network_snapshot(&self, pid: u32) -> Option<NetworkSnapshot> {
        let (inodes, inode_limited) = read_socket_inodes(pid)?;
        let (sockets, socket_limited) = read_network_sockets(pid)?;
        Some(NetworkSnapshot {
            inodes,
            sockets,
            limited: inode_limited || socket_limited,
        })
    }
}

fn current_processes() -> ProcessSnapshot {
    let Ok(entries) = fs::read_dir("/proc") else {
        return ProcessSnapshot {
            processes: HashMap::new(),
            available: false,
            unreadable_pids: HashSet::new(),
        };
    };

    let mut processes = HashMap::new();
    let mut unreadable_pids = HashSet::new();
    for entry in entries.filter_map(Result::ok) {
        let Some(pid) = entry.file_name().to_string_lossy().parse().ok() else {
            continue;
        };
        match read_process_info(pid) {
            Some(info) => {
                processes.insert(pid, info);
            }
            None => {
                unreadable_pids.insert(pid);
            }
        }
    }
    ProcessSnapshot {
        processes,
        available: true,
        unreadable_pids,
    }
}

fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let command_end = stat.rfind(") ")?;
    let command_start = stat.find('(')? + 1;
    let fields = stat[command_end + 2..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let state = fields.first()?.chars().next()?;
    let parent_pid = fields.get(1)?.parse().ok()?;
    let user_cpu_ticks = fields.get(11).and_then(|value| value.parse().ok());
    let system_cpu_ticks = fields.get(12).and_then(|value| value.parse().ok());
    let comm = &stat[command_start..command_end];
    let command =
        read_command_line(pid).unwrap_or_else(|| format!("[{}]", sanitize_process_text(comm)));
    let (read_storage_bytes, write_storage_bytes) = read_process_io(pid);

    Some(ProcessInfo {
        pid,
        parent_pid,
        state,
        command,
        user_cpu_ticks,
        system_cpu_ticks,
        resident_memory_kib: read_resident_memory_kib(pid),
        read_storage_bytes,
        write_storage_bytes,
    })
}

fn read_process_io(pid: u32) -> (Option<u64>, Option<u64>) {
    let Ok(io) = fs::read_to_string(format!("/proc/{pid}/io")) else {
        return (None, None);
    };

    let mut read_storage_bytes = None;
    let mut write_storage_bytes = None;
    for line in io.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("read_bytes:") => {
                read_storage_bytes = fields.next().and_then(|value| value.parse().ok())
            }
            Some("write_bytes:") => {
                write_storage_bytes = fields.next().and_then(|value| value.parse().ok())
            }
            _ => {}
        }
    }
    (read_storage_bytes, write_storage_bytes)
}

fn read_resident_memory_kib(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? != "VmRSS:" {
            return None;
        }
        let value = fields.next()?.parse().ok()?;
        (fields.next()? == "kB").then_some(value)
    })
}

fn read_command_line(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command = bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| sanitize_process_text(&String::from_utf8_lossy(argument)))
        .collect::<Vec<_>>()
        .join(" ");
    (!command.is_empty()).then_some(command)
}

#[cfg(target_os = "linux")]
pub(crate) fn clock_ticks_per_second() -> Option<u64> {
    let ticks = unsafe { sysconf(SC_CLK_TCK) };
    u64::try_from(ticks).ok().filter(|ticks| *ticks > 0)
}

#[cfg(not(target_os = "linux"))]
fn clock_ticks_per_second() -> Option<u64> {
    None
}

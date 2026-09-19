use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use crate::filesystem::FilesystemObservation;
use crate::formatting::{
    MAX_DETAIL_ITEMS, format_duration, format_examples, format_path_examples, pluralize,
    sanitize_process_text, signal_name,
};
use crate::network::{NetworkObservation, SocketRecord};
use crate::platform::clock_ticks_per_second;

const EXCESSIVE_SCAN_PATHS: usize = 25;

pub(crate) struct ProcessObservation {
    root_pid: u32,
    primary: Option<ObservedProcess>,
    descendants: BTreeMap<u32, ObservedProcess>,
    peak_resident_memory_kib: Option<u64>,
    filesystem: FilesystemObservation,
    network: NetworkObservation,
    limitations: ObservationLimitations,
}

#[derive(Default)]
struct ObservationLimitations {
    process: bool,
    resources: bool,
    filesystem: bool,
    network: bool,
    working_directory: bool,
}

pub(crate) struct ProcessSnapshot {
    pub(crate) processes: HashMap<u32, ProcessInfo>,
    pub(crate) available: bool,
    pub(crate) unreadable_pids: HashSet<u32>,
}

pub(crate) trait ObservationBoundary {
    fn process_snapshot(&self) -> ProcessSnapshot;
    fn file_descriptors(&self, pid: u32) -> Option<FileDescriptorSnapshot>;
    fn network_snapshot(&self, pid: u32) -> Option<NetworkSnapshot>;
}

pub(crate) struct LinuxObservationBoundary;

pub(crate) struct FileDescriptor {
    pub(crate) path: PathBuf,
    pub(crate) directory: bool,
    pub(crate) read: bool,
    pub(crate) write: bool,
}

pub(crate) struct FileDescriptorSnapshot {
    pub(crate) descriptors: Vec<FileDescriptor>,
    pub(crate) limited: bool,
}

pub(crate) struct NetworkSnapshot {
    pub(crate) inodes: HashSet<u64>,
    pub(crate) sockets: HashMap<u64, SocketRecord>,
    pub(crate) limited: bool,
}

struct ObservedProcess {
    info: ProcessInfo,
    depth: usize,
}

#[derive(Clone)]
pub(crate) struct ProcessInfo {
    pub(crate) pid: u32,
    pub(crate) parent_pid: u32,
    pub(crate) state: char,
    pub(crate) command: String,
    pub(crate) user_cpu_ticks: Option<u64>,
    pub(crate) system_cpu_ticks: Option<u64>,
    pub(crate) resident_memory_kib: Option<u64>,
    pub(crate) read_storage_bytes: Option<u64>,
    pub(crate) write_storage_bytes: Option<u64>,
}

impl ProcessObservation {
    pub(crate) fn new(root_pid: u32, working_directory: Option<PathBuf>) -> Self {
        Self {
            root_pid,
            primary: None,
            descendants: BTreeMap::new(),
            peak_resident_memory_kib: None,
            filesystem: FilesystemObservation::new(working_directory),
            network: NetworkObservation::new(),
            limitations: ObservationLimitations::default(),
        }
    }

    pub(crate) fn observe<B: ObservationBoundary>(
        &mut self,
        boundary: &B,
        root_expected_alive: bool,
    ) {
        let snapshot = boundary.process_snapshot();
        let snapshot_available = snapshot.available;
        let processes = snapshot.processes;
        let root_available = processes.contains_key(&self.root_pid);
        let known_process_unreadable = snapshot.unreadable_pids.contains(&self.root_pid)
            || self
                .descendants
                .keys()
                .any(|pid| snapshot.unreadable_pids.contains(pid));
        if !snapshot_available
            || !snapshot.unreadable_pids.is_empty()
            || known_process_unreadable
            || (root_expected_alive && !root_available)
        {
            self.limitations.process = true;
        }
        let mut current_tree = HashSet::new();

        if let Some(info) = processes.get(&self.root_pid) {
            current_tree.insert(self.root_pid);
            match &mut self.primary {
                Some(primary) => primary.update(info),
                None => {
                    self.primary = Some(ObservedProcess {
                        info: info.clone(),
                        depth: 0,
                    });
                }
            }
        }

        let mut children = HashMap::<u32, Vec<u32>>::new();
        for info in processes.values() {
            children.entry(info.parent_pid).or_default().push(info.pid);
        }

        let mut pending = vec![(self.root_pid, 0)];
        let mut seen = HashSet::new();
        seen.insert(self.root_pid);

        while let Some((parent_pid, parent_depth)) = pending.pop() {
            let Some(child_pids) = children.get(&parent_pid) else {
                continue;
            };

            for child_pid in child_pids {
                if !seen.insert(*child_pid) {
                    continue;
                }

                let Some(info) = processes.get(child_pid) else {
                    continue;
                };
                if root_available {
                    current_tree.insert(*child_pid);
                }
                let depth = parent_depth + 1;
                match self.descendants.get_mut(child_pid) {
                    Some(descendant) => descendant.update(info),
                    None => {
                        self.descendants.insert(
                            *child_pid,
                            ObservedProcess {
                                info: info.clone(),
                                depth,
                            },
                        );
                    }
                }
                pending.push((*child_pid, depth));
            }
        }

        if current_tree.iter().any(|pid| {
            processes.get(pid).is_some_and(|info| {
                info.is_alive()
                    && (info.user_cpu_ticks.is_none()
                        || info.system_cpu_ticks.is_none()
                        || info.resident_memory_kib.is_none())
            })
        }) {
            self.limitations.resources = true;
        }
        self.update_peak_memory(&processes, &current_tree);
        self.filesystem.observe(boundary, &processes, &current_tree);
        self.network.observe(boundary, &processes, &current_tree);
        self.limitations.filesystem |= self.filesystem.is_limited();
        self.limitations.network |= self.network.is_limited();
    }

    pub(crate) fn print_report<B: ObservationBoundary>(
        &mut self,
        boundary: &B,
        command: &str,
        duration: Duration,
        exit_code: Option<i32>,
        termination_signal: Option<i32>,
    ) {
        let snapshot = boundary.process_snapshot();
        let known_process_unreadable = snapshot.unreadable_pids.contains(&self.root_pid)
            || self
                .descendants
                .keys()
                .any(|pid| snapshot.unreadable_pids.contains(pid));
        let process_snapshot_available =
            snapshot.available && !known_process_unreadable && self.primary.is_some();
        let processes = snapshot.processes;
        if !process_snapshot_available {
            self.limitations.process = true;
            self.limitations.resources = true;
        }
        self.network
            .observe_pids(boundary, &processes, self.descendants.keys().copied());
        self.limitations.network |= self.network.is_limited();
        self.limitations.working_directory |= !self.filesystem.has_working_directory();

        eprintln!("\nRunLens report");
        eprintln!("Command: {command}");
        eprintln!("Duration and resources:");
        eprintln!("  Duration: {}", format_duration(duration));
        match (exit_code, termination_signal) {
            (Some(code), _) => eprintln!("  Exit status: {code}"),
            (None, Some(signal)) => eprintln!(
                "  Exit status: terminated by signal {} ({signal})",
                signal_name(signal)
            ),
            (None, None) => eprintln!("  Exit status: terminated by signal"),
        }
        self.print_resource_report();

        eprintln!("Processes:");
        self.print_process_report(&processes, process_snapshot_available);

        eprintln!("Filesystem:");
        self.filesystem.print_report();

        eprintln!("Network:");
        self.network
            .print_report(&processes, process_snapshot_available);

        self.print_observation_limitations();
        self.print_findings(&processes, exit_code);
    }

    fn print_process_report(
        &self,
        processes: &HashMap<u32, ProcessInfo>,
        process_snapshot_available: bool,
    ) {
        let descendant_label = pluralize(self.descendants.len(), "descendant", "descendants");
        if process_snapshot_available {
            eprintln!(
                "  Process count: {} {descendant_label}",
                self.descendants.len()
            );
        } else {
            eprintln!("  Process count: unavailable");
        }
        eprintln!("  Process tree:");
        if let Some(primary) = &self.primary {
            primary.print(1);
        } else {
            eprintln!("    - primary process unavailable");
        }
        for descendant in self.descendants.values() {
            descendant.print(descendant.depth + 1);
        }

        if process_snapshot_available {
            let survivors = self
                .descendants
                .values()
                .filter(|descendant| {
                    processes
                        .get(&descendant.info.pid)
                        .is_some_and(ProcessInfo::is_alive)
                })
                .collect::<Vec<_>>();
            eprintln!("  Surviving descendants: {}", survivors.len());
            for survivor in survivors {
                survivor.print(2);
            }
        } else {
            eprintln!("  Surviving descendants: unavailable");
        }
    }

    fn print_resource_report(&self) {
        eprintln!("  Resource usage:");
        let user_cpu = (!self.limitations.resources)
            .then(|| self.aggregate_cpu_millis(true))
            .flatten();
        match user_cpu {
            Some(milliseconds) => eprintln!("    Aggregate user CPU: {milliseconds} ms"),
            None => eprintln!("    Aggregate user CPU: unavailable"),
        }
        let system_cpu = (!self.limitations.resources)
            .then(|| self.aggregate_cpu_millis(false))
            .flatten();
        match system_cpu {
            Some(milliseconds) => eprintln!("    Aggregate system CPU: {milliseconds} ms"),
            None => eprintln!("    Aggregate system CPU: unavailable"),
        }
        match (!self.limitations.resources)
            .then_some(self.peak_resident_memory_kib)
            .flatten()
        {
            Some(kib) => eprintln!("    Peak aggregate resident memory: {kib} KiB"),
            None => eprintln!("    Peak aggregate resident memory: unavailable"),
        }
    }

    fn print_observation_limitations(&self) {
        let mut limitations = Vec::new();
        if self.limitations.process {
            limitations.push(
                "process metadata was unavailable or incomplete; process counts and survivor checks may miss activity",
            );
        }
        if self.limitations.resources {
            limitations.push(
                "CPU or memory counters were unavailable for part of the observed process tree",
            );
        }
        if self.limitations.filesystem {
            limitations.push(
                "filesystem descriptors or I/O counters were unavailable; path and byte totals may be incomplete",
            );
        }
        if self.limitations.network {
            limitations.push(
                "network metadata was unavailable or restricted; connection activity may be incomplete",
            );
        }
        if self.limitations.working_directory {
            limitations.push(
                "working-directory boundary was unavailable; inside/outside path classification may be incomplete",
            );
        }

        if limitations.is_empty() {
            eprintln!("Observation limitations: none");
        } else {
            eprintln!("Observation limitations:");
            for limitation in limitations {
                eprintln!("  - {limitation}");
            }
        }
    }

    fn print_findings(&self, processes: &HashMap<u32, ProcessInfo>, exit_code: Option<i32>) {
        let mut findings = Vec::new();

        let survivors = self
            .descendants
            .values()
            .filter(|descendant| {
                processes
                    .get(&descendant.info.pid)
                    .is_some_and(ProcessInfo::is_alive)
            })
            .collect::<Vec<_>>();
        for survivor in survivors {
            findings.push(format!(
                "surviving descendant PID {} ({}) remains alive; inspect or stop it after confirming it is not needed",
                survivor.info.pid,
                sanitize_process_text(&survivor.info.command),
            ));
        }

        let scanned_paths = self.filesystem.scanned_path_count();
        if scanned_paths >= EXCESSIVE_SCAN_PATHS {
            findings.push(format!(
                "excessive file/directory scanning: {scanned_paths} distinct paths observed; inspect the command's scan scope"
            ));
        }

        let outside_paths = self.filesystem.outside_paths();
        if !outside_paths.is_empty() {
            findings.push(format!(
                "activity outside working directory: {} path(s) observed; verify each path is expected ({})",
                outside_paths.len(),
                format_path_examples(&outside_paths),
            ));
        }

        let sensitive_paths = self.filesystem.sensitive_paths();
        if !sensitive_paths.is_empty() {
            findings.push(format!(
                "sensitive path access: {} path(s) observed; review permissions and data exposure ({})",
                sensitive_paths.len(),
                format_path_examples(&sensitive_paths),
            ));
        }

        let remote_connections = self.network.remote_connections();
        if !remote_connections.is_empty() {
            let endpoints = remote_connections
                .iter()
                .take(MAX_DETAIL_ITEMS)
                .map(|connection| {
                    format!(
                        "{} {}",
                        connection.protocol_label(),
                        connection.remote_endpoint()
                    )
                })
                .collect::<Vec<_>>();
            findings.push(format!(
                "remote/unexpected network activity: {} connection(s) observed; verify destination and port ({})",
                remote_connections.len(),
                format_examples(&endpoints, remote_connections.len()),
            ));
        }

        if let Some(code) = exit_code.filter(|code| *code != 0) {
            findings.push(format!(
                "command exited with status {code}; inspect command output and the findings above"
            ));
        }

        if findings.is_empty() {
            eprintln!("Notable findings: none");
        } else {
            eprintln!("Notable findings:");
            for finding in findings {
                eprintln!("  - {finding}");
            }
        }
    }

    fn aggregate_cpu_millis(&self, user: bool) -> Option<u64> {
        self.primary.as_ref()?;
        let ticks = self
            .primary
            .iter()
            .chain(self.descendants.values())
            .try_fold(0_u64, |total, process| {
                let process_ticks = if user {
                    process.info.user_cpu_ticks?
                } else {
                    process.info.system_cpu_ticks?
                };
                total.checked_add(process_ticks)
            })?;
        let ticks_per_second = clock_ticks_per_second()?;
        let milliseconds = u128::from(ticks)
            .checked_mul(1_000)?
            .checked_div(u128::from(ticks_per_second))?;
        u64::try_from(milliseconds).ok()
    }

    fn update_peak_memory(
        &mut self,
        processes: &HashMap<u32, ProcessInfo>,
        current_tree: &HashSet<u32>,
    ) {
        if current_tree.is_empty() {
            return;
        }
        let Some(total) = current_tree.iter().try_fold(0_u64, |total, pid| {
            total.checked_add(processes.get(pid)?.resident_memory_kib?)
        }) else {
            return;
        };

        self.peak_resident_memory_kib = Some(
            self.peak_resident_memory_kib
                .map_or(total, |peak| peak.max(total)),
        );
    }
}

impl ObservedProcess {
    fn update(&mut self, info: &ProcessInfo) {
        self.info.state = info.state;
        self.info.command.clone_from(&info.command);
        if info.user_cpu_ticks.is_some() {
            self.info.user_cpu_ticks = info.user_cpu_ticks;
        }
        if info.system_cpu_ticks.is_some() {
            self.info.system_cpu_ticks = info.system_cpu_ticks;
        }
        if info.resident_memory_kib.is_some() {
            self.info.resident_memory_kib = info.resident_memory_kib;
        }
        if info.read_storage_bytes.is_some() {
            self.info.read_storage_bytes = info.read_storage_bytes;
        }
        if info.write_storage_bytes.is_some() {
            self.info.write_storage_bytes = info.write_storage_bytes;
        }
    }

    fn print(&self, depth: usize) {
        let indent = "  ".repeat(depth);
        eprintln!(
            "{indent}- PID {} (parent PID {}): {}",
            self.info.pid, self.info.parent_pid, self.info.command
        );
    }
}

impl ProcessInfo {
    pub(crate) fn is_alive(&self) -> bool {
        !matches!(self.state, 'Z' | 'X')
    }
}

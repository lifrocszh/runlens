use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::formatting::{is_sensitive_path, print_path_samples};
use crate::observation::{ObservationBoundary, ProcessInfo};

pub(crate) struct FilesystemObservation {
    working_directory: Option<PathBuf>,
    paths: BTreeMap<PathBuf, FileAccess>,
    directories: BTreeMap<PathBuf, FileAccess>,
    observed_pids: HashSet<u32>,
    initial_io: HashMap<u32, IoCounters>,
    latest_io: HashMap<u32, IoCounters>,
    missing_initial_read: HashSet<u32>,
    missing_initial_write: HashSet<u32>,
    paths_limited: bool,
}

#[derive(Default)]
struct IoCounters {
    read: Option<u64>,
    write: Option<u64>,
}

#[derive(Default)]
struct FileAccess {
    read: bool,
    write: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PathArea {
    Inside,
    Outside,
    Unknown,
}

impl FilesystemObservation {
    pub(crate) fn new(working_directory: Option<PathBuf>) -> Self {
        Self {
            working_directory,
            paths: BTreeMap::new(),
            directories: BTreeMap::new(),
            observed_pids: HashSet::new(),
            initial_io: HashMap::new(),
            latest_io: HashMap::new(),
            missing_initial_read: HashSet::new(),
            missing_initial_write: HashSet::new(),
            paths_limited: false,
        }
    }

    pub(crate) fn observe<B: ObservationBoundary>(
        &mut self,
        boundary: &B,
        processes: &HashMap<u32, ProcessInfo>,
        current_tree: &HashSet<u32>,
    ) {
        for pid in current_tree {
            let Some(info) = processes.get(pid) else {
                continue;
            };
            self.observe_io(*pid, info);
            if info.is_alive() {
                self.observe_paths(boundary, *pid);
            }
        }
    }

    fn observe_io(&mut self, pid: u32, info: &ProcessInfo) {
        if self.observed_pids.insert(pid) {
            if info.read_storage_bytes.is_none() {
                self.missing_initial_read.insert(pid);
            }
            if info.write_storage_bytes.is_none() {
                self.missing_initial_write.insert(pid);
            }
        }

        if !self.missing_initial_read.contains(&pid) {
            let initial = self.initial_io.entry(pid).or_default();
            if initial.read.is_none() {
                initial.read = info.read_storage_bytes;
            }
        }
        if !self.missing_initial_write.contains(&pid) {
            let initial = self.initial_io.entry(pid).or_default();
            if initial.write.is_none() {
                initial.write = info.write_storage_bytes;
            }
        }

        let latest = self.latest_io.entry(pid).or_default();
        if info.read_storage_bytes.is_some() {
            latest.read = info.read_storage_bytes;
        }
        if info.write_storage_bytes.is_some() {
            latest.write = info.write_storage_bytes;
        }
    }

    fn observe_paths<B: ObservationBoundary>(&mut self, boundary: &B, pid: u32) {
        let Some(snapshot) = boundary.file_descriptors(pid) else {
            self.paths_limited = true;
            return;
        };
        self.paths_limited |= snapshot.limited;

        for descriptor in snapshot.descriptors {
            let paths = if descriptor.directory {
                &mut self.directories
            } else {
                &mut self.paths
            };
            if !descriptor.read && !descriptor.write {
                continue;
            }

            let access = paths.entry(descriptor.path).or_default();
            access.read |= descriptor.read;
            access.write |= descriptor.write;
        }
    }

    pub(crate) fn print_report(&self) {
        if self.observed_pids.is_empty() {
            eprintln!("  Filesystem activity: unavailable");
            self.print_limits();
            return;
        }

        let has_activity = !self.paths.is_empty()
            || !self.directories.is_empty()
            || self.bytes_for_report(true).is_some_and(|bytes| bytes > 0)
            || self.bytes_for_report(false).is_some_and(|bytes| bytes > 0);
        if !has_activity {
            eprintln!("  Filesystem activity: none observed");
            self.print_limits();
            return;
        }

        eprintln!("  Filesystem activity:");
        match self.bytes_for_report(true) {
            Some(bytes) => eprintln!("    Read bytes: {bytes} bytes"),
            None => eprintln!("    Read bytes: unavailable"),
        }
        match self.bytes_for_report(false) {
            Some(bytes) => eprintln!("    Write bytes: {bytes} bytes"),
            None => eprintln!("    Write bytes: unavailable"),
        }

        if self.working_directory.is_some() {
            self.print_area("Inside working directory", PathArea::Inside);
            self.print_area("Outside working directory", PathArea::Outside);
        } else {
            eprintln!("    Working directory boundary: unavailable");
            self.print_area("Unclassified paths", PathArea::Unknown);
        }

        self.print_limits();
    }

    fn print_limits(&self) {
        let mut limits = vec![
            "paths and counts are sampled from open descriptors; read/write-capable does not prove a completed operation and short-lived activity may be missed"
                .to_owned(),
        ];
        if self.paths_limited {
            limits.push("some process file descriptors were not readable".to_owned());
        }
        if !self.missing_initial_read.is_empty() || !self.missing_initial_write.is_empty() {
            limits.push("one or more I/O counters were unavailable".to_owned());
        }
        if self.bytes_for_report(true).is_none() && self.has_access(true) {
            limits.push("read byte totals may miss short-lived process activity".to_owned());
        }
        if self.bytes_for_report(false).is_none() && self.has_access(false) {
            limits.push("write byte totals may miss short-lived process activity".to_owned());
        }
        limits.push(
            "byte totals are kernel-reported storage I/O bytes, may exclude cached activity, and are not path-specific totals"
                .to_owned(),
        );
        eprintln!("  Filesystem observation limits: {}.", limits.join("; "));
    }

    pub(crate) fn scanned_path_count(&self) -> usize {
        self.paths.len() + self.directories.len()
    }

    pub(crate) fn outside_paths(&self) -> Vec<PathBuf> {
        self.all_paths()
            .filter(|path| self.path_area(path) == PathArea::Outside)
            .cloned()
            .collect()
    }

    pub(crate) fn sensitive_paths(&self) -> Vec<PathBuf> {
        self.all_paths()
            .filter(|path| is_sensitive_path(path))
            .cloned()
            .collect()
    }

    fn all_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.paths.keys().chain(self.directories.keys())
    }

    fn aggregate_bytes(&self, read: bool) -> Option<u64> {
        let missing = if read {
            &self.missing_initial_read
        } else {
            &self.missing_initial_write
        };
        if !missing.is_empty() {
            return None;
        }

        self.observed_pids.iter().try_fold(0_u64, |total, pid| {
            let initial = self.initial_io.get(pid)?;
            let latest = self.latest_io.get(pid)?;
            let (initial, latest) = if read {
                (initial.read?, latest.read?)
            } else {
                (initial.write?, latest.write?)
            };
            total.checked_add(latest.checked_sub(initial)?)
        })
    }

    pub(crate) fn is_limited(&self) -> bool {
        self.observed_pids.is_empty()
            || self.paths_limited
            || !self.missing_initial_read.is_empty()
            || !self.missing_initial_write.is_empty()
            || (self.bytes_for_report(true).is_none() && self.has_access(true))
            || (self.bytes_for_report(false).is_none() && self.has_access(false))
    }

    pub(crate) fn has_working_directory(&self) -> bool {
        self.working_directory.is_some()
    }

    fn bytes_for_report(&self, read: bool) -> Option<u64> {
        let bytes = self.aggregate_bytes(read)?;
        (!self.has_access(read) || bytes > 0).then_some(bytes)
    }

    fn has_access(&self, read: bool) -> bool {
        self.paths
            .values()
            .any(|access| if read { access.read } else { access.write })
    }

    fn print_area(&self, title: &str, area: PathArea) {
        let read_paths = self
            .paths
            .iter()
            .filter(|(path, access)| access.read && self.path_area(path) == area)
            .map(|(path, _)| path)
            .collect::<Vec<_>>();
        let write_paths = self
            .paths
            .iter()
            .filter(|(path, access)| access.write && self.path_area(path) == area)
            .map(|(path, _)| path)
            .collect::<Vec<_>>();

        let read_directories = self
            .directories
            .iter()
            .filter(|(path, access)| access.read && self.path_area(path) == area)
            .map(|(path, _)| path)
            .collect::<Vec<_>>();
        let write_directories = self
            .directories
            .iter()
            .filter(|(path, access)| access.write && self.path_area(path) == area)
            .map(|(path, _)| path)
            .collect::<Vec<_>>();

        if read_paths.is_empty()
            && read_directories.is_empty()
            && write_paths.is_empty()
            && write_directories.is_empty()
        {
            return;
        }

        eprintln!("  {title}:");
        eprintln!("    Read-capable files: {}", read_paths.len());
        eprintln!("    Read-capable directories: {}", read_directories.len());
        if !read_paths.is_empty() {
            print_path_samples("    Read paths", &read_paths);
        }
        if !read_directories.is_empty() {
            print_path_samples("    Read directories", &read_directories);
        }
        eprintln!("    Write-capable files: {}", write_paths.len());
        eprintln!("    Write-capable directories: {}", write_directories.len());
        if !write_paths.is_empty() {
            print_path_samples("    Write paths", &write_paths);
        }
        if !write_directories.is_empty() {
            print_path_samples("    Write directories", &write_directories);
        }
    }

    fn path_area(&self, path: &Path) -> PathArea {
        let Some(working_directory) = &self.working_directory else {
            return PathArea::Unknown;
        };
        if path.starts_with(working_directory) {
            PathArea::Inside
        } else {
            PathArea::Outside
        }
    }
}

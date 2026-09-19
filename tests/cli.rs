use std::fs;
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::raw::{c_int, c_ulong};
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: c_int, arg2: c_ulong, arg3: c_ulong, arg4: c_ulong, arg5: c_ulong) -> c_int;
}

#[cfg(target_os = "linux")]
const PR_SET_DUMPABLE: c_int = 4;

fn runlens(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runlens"))
        .args(args)
        .output()
        .expect("runlens should start")
}

fn runlens_in(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runlens"))
        .current_dir(directory)
        .args(args)
        .output()
        .expect("runlens should start")
}

#[cfg(target_os = "linux")]
fn runlens_with_env(args: &[String], environment: &[(&str, &str)]) -> Output {
    runlens_in_with_env(Path::new("."), args, environment)
}

#[cfg(target_os = "linux")]
fn runlens_in_with_env(directory: &Path, args: &[String], environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_runlens"));
    command.current_dir(directory);
    command.args(args);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().expect("runlens should start")
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("runlens-{label}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).expect("test directory should be created");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct SurvivorCleanup {
    marker: PathBuf,
    pid: Option<u32>,
}

impl SurvivorCleanup {
    fn new(marker: PathBuf) -> Self {
        let _ = fs::remove_file(&marker);
        Self { marker, pid: None }
    }
}

impl Drop for SurvivorCleanup {
    fn drop(&mut self) {
        let pid = self
            .pid
            .or_else(|| fs::read_to_string(&self.marker).ok()?.trim().parse().ok());
        if let Some(pid) = pid.filter(|pid| process_is_alive(*pid)) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .status();
            for _ in 0..50 {
                if !process_is_alive(pid) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        let _ = fs::remove_file(&self.marker);
    }
}

#[cfg(target_os = "linux")]
struct LoopbackListener {
    address: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl LoopbackListener {
    fn new() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
        let address = listener
            .local_addr()
            .expect("loopback listener should have an address")
            .to_string();
        Self::from_listener(listener, address)
    }

    fn non_loopback() -> Option<Self> {
        let route = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
        route.connect(("198.51.100.1", 9)).ok()?;
        let address = route.local_addr().ok()?.ip();
        if address.is_loopback() || address.is_unspecified() {
            return None;
        }

        let listener = TcpListener::bind(("0.0.0.0", 0)).ok()?;
        let port = listener.local_addr().ok()?.port();
        Some(Self::from_listener(
            listener,
            SocketAddr::new(address, port).to_string(),
        ))
    }

    fn from_listener(listener: TcpListener, address: String) -> Self {
        listener
            .set_nonblocking(true)
            .expect("fixture listener should become nonblocking");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        while !thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                            thread::sleep(Duration::from_millis(5));
                        }
                        drop(stream);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });

        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LoopbackListener {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn process_is_alive(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(command_end) = stat.rfind(") ") else {
        return false;
    };
    !matches!(stat[command_end + 2..].chars().next(), Some('Z' | 'X'))
}

fn resource_value(report: &str, label: &str, unit: &str) -> Option<u64> {
    let line = report
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("missing {label} in report:\n{report}"));
    let value = line
        .strip_prefix(label)
        .expect("resource label should match")
        .trim();
    if value == "unavailable" {
        return None;
    }
    Some(
        value
            .strip_suffix(unit)
            .unwrap_or_else(|| panic!("missing {unit} in {line:?}"))
            .trim()
            .parse()
            .unwrap_or_else(|error| panic!("invalid resource value in {line:?}: {error}")),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn network_fixture() {
    let Ok(address) = std::env::var("RUNLENS_NETWORK_FIXTURE_ADDR") else {
        return;
    };

    let mut stream = TcpStream::connect(address).expect("network fixture should connect");
    stream
        .write_all(b"runlens-network-payload-must-not-appear")
        .expect("network fixture should write payload");
    if let Ok(marker) = std::env::var("RUNLENS_NETWORK_FIXTURE_PID_FILE") {
        fs::write(marker, std::process::id().to_string())
            .expect("network fixture should record its PID");
    }
    let hold_millis = std::env::var("RUNLENS_NETWORK_FIXTURE_HOLD_MILLIS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(250);
    thread::sleep(Duration::from_millis(hold_millis));
}

#[cfg(target_os = "linux")]
#[test]
fn complete_fixture() {
    let Ok(scan_directory) = std::env::var("RUNLENS_COMPLETE_SCAN_DIRECTORY") else {
        return;
    };
    let Ok(outside_sensitive_path) = std::env::var("RUNLENS_COMPLETE_SENSITIVE_PATH") else {
        return;
    };
    let Ok(network_address) = std::env::var("RUNLENS_COMPLETE_NETWORK_ADDRESS") else {
        return;
    };
    let Ok(survivor_marker) = std::env::var("RUNLENS_COMPLETE_SURVIVOR_MARKER") else {
        return;
    };

    let mut open_files = Vec::new();
    let mut entries = fs::read_dir(&scan_directory)
        .expect("complete fixture scan directory should be readable")
        .collect::<Result<Vec<_>, _>>()
        .expect("complete fixture scan entries should be readable");
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let mut file = File::open(entry.path()).expect("complete fixture file should open");
        let mut contents = [0_u8; 1];
        file.read_exact(&mut contents)
            .expect("complete fixture file should be read");
        open_files.push(file);
    }
    open_files.push(File::open(&scan_directory).expect("scan directory should open"));

    let mut sensitive_file =
        File::open(outside_sensitive_path).expect("complete fixture sensitive path should open");
    let mut contents = [0_u8; 1];
    sensitive_file
        .read_exact(&mut contents)
        .expect("complete fixture sensitive path should be read");
    open_files.push(sensitive_file);

    let writable_path = PathBuf::from(&std::env::var("RUNLENS_COMPLETE_WRITABLE_PATH").unwrap());
    let mut writable_file = OpenOptions::new()
        .write(true)
        .open(writable_path)
        .expect("complete fixture output should open");
    writable_file
        .write_all(b"fixture-write")
        .expect("complete fixture output should be written");
    open_files.push(writable_file);

    let mut stream = TcpStream::connect(network_address)
        .expect("complete fixture network listener should accept connections");
    stream
        .write_all(b"runlens-complete-fixture-payload-must-not-appear")
        .expect("complete fixture network payload should be written");

    let survivor = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("complete fixture survivor should start");
    fs::write(survivor_marker, survivor.id().to_string())
        .expect("complete fixture survivor marker should be written");
    std::mem::forget(survivor);

    thread::sleep(Duration::from_millis(1_000));
    drop(stream);
    drop(open_files);
}

#[cfg(target_os = "linux")]
#[test]
fn partial_observation_fixture() {
    let Ok(marker) = std::env::var("RUNLENS_PARTIAL_OBSERVATION_MARKER") else {
        return;
    };

    let result = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(result, 0, "fixture should restrict /proc observation");
    fs::write(marker, "ready").expect("partial observation fixture should write marker");
    thread::sleep(Duration::from_millis(500));
}

#[test]
fn passes_arguments_unchanged() {
    let output = runlens(&[
        "/bin/sh",
        "-c",
        "printf '<%s><%s>' \"$1\" \"$2\"",
        "fixture",
        "a b",
        "x;y",
    ]);

    assert!(output.status.success());
    assert_eq!(output.stdout, b"<a b><x;y>");
}

#[test]
fn preserves_stdout_and_stderr() {
    let output = runlens(&["/bin/sh", "-c", "printf stdout; printf stderr >&2"]);

    assert_eq!(output.stdout, b"stdout");
    assert!(output.stderr.starts_with(b"stderr\nRunLens report"));
}

#[test]
fn reports_success_with_command_duration_and_exit_status() {
    let output = runlens(&["/bin/sh", "-c", "printf command-output"]);

    assert!(output.status.success());
    assert_eq!(output.stdout, b"command-output");

    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("RunLens report"));
    assert!(report.contains("Command: /bin/sh -c 'printf command-output'"));
    assert!(report.contains("Duration: "));
    assert!(report.contains("Exit status: 0"));
}

#[test]
fn report_keeps_argument_boundaries_visible() {
    let output = runlens(&["/bin/sh", "-c", "exit 0", "fixture", "two words"]);

    assert!(output.status.success());
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Command: /bin/sh -c 'exit 0' fixture 'two words'"));
}

#[test]
fn preserves_failed_exit_status_and_reports_failure() {
    let output = runlens(&["/bin/sh", "-c", "printf failed >&2; exit 7"]);

    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(stderr.starts_with("failed"));
    assert!(stderr.contains("Exit status: 7"));
    assert!(stderr.contains("command exited with status 7"));
}

#[test]
fn distinguishes_launch_failure_from_wrapped_failure() {
    let output = runlens(&["/definitely/not/a/real/runlens-command"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());

    let stderr = String::from_utf8(output.stderr).expect("diagnostic should be UTF-8");
    assert!(stderr.contains("runlens: failed to launch"));
    assert!(stderr.contains("report not produced"));
    assert!(!stderr.contains("RunLens report"));
    assert!(!stderr.contains("Exit status:"));
}

#[cfg(target_os = "linux")]
#[test]
fn forwards_signal_and_preserves_signal_termination() {
    let sandbox = TestDirectory::new("signal");
    let marker_path = sandbox.path.join("child.pid");
    let mut cleanup = SurvivorCleanup::new(marker_path.clone());
    let marker = marker_path.to_string_lossy().into_owned();
    let runlens = Command::new(env!("CARGO_BIN_EXE_runlens"))
        .args([
            "/bin/sh",
            "-c",
            "printf '%s' $$ > \"$1\"; exec >/dev/null 2>/dev/null; exec sleep 30",
            "signal-fixture",
        ])
        .arg(&marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("runlens should start signal fixture");

    for _ in 0..100 {
        if marker_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let child_pid = fs::read_to_string(&marker_path)
        .expect("signal fixture should write child PID")
        .parse::<u32>()
        .expect("signal fixture PID should be numeric");
    cleanup.pid = Some(child_pid);

    let kill_status = Command::new("kill")
        .arg("-TERM")
        .arg(runlens.id().to_string())
        .status()
        .expect("kill should start");
    assert!(kill_status.success());
    let output = runlens
        .wait_with_output()
        .expect("runlens should finish after signal");

    assert_eq!(output.status.signal(), Some(15));
    assert!(
        !process_is_alive(child_pid),
        "child should receive forwarded signal"
    );
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(
        report.contains("Exit status: terminated by signal SIGTERM (15)"),
        "{report}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn reports_partial_observation_without_false_zeroes() {
    let sandbox = TestDirectory::new("partial-observation");
    let marker = sandbox.path.join("ready");
    let fixture = std::env::current_exe()
        .expect("test executable should be available")
        .to_string_lossy()
        .into_owned();
    let args = vec![
        fixture,
        "--exact".to_owned(),
        "partial_observation_fixture".to_owned(),
        "--nocapture".to_owned(),
    ];
    let marker = marker.to_string_lossy().into_owned();
    let output = runlens_with_env(
        &args,
        &[("RUNLENS_PARTIAL_OBSERVATION_MARKER", marker.as_str())],
    );

    assert!(output.status.success());
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Observation limitations:"), "{report}");
    assert!(
        report.contains("unavailable") || report.contains("incomplete"),
        "{report}"
    );
    assert!(!report.contains("Read bytes: 0 bytes"), "{report}");
}

#[test]
fn reports_descendant_count_and_parent_relationships() {
    let output = runlens(&["/bin/sh", "-c", "sleep 0.2; exit 0"]);

    assert!(output.status.success());

    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Process count: 1"), "{report}");
    assert!(report.contains("Process tree:"), "{report}");
    assert!(report.contains("parent PID"), "{report}");
    assert!(report.contains("sleep 0.2"), "{report}");
}

#[test]
fn reports_aggregate_cpu_and_peak_resident_memory() {
    let output = runlens(&[
        "/bin/sh",
        "-c",
        "awk 'BEGIN { for (i = 0; i < 20000000; i++) total += i }'; sleep 0.05",
    ]);

    assert!(output.status.success());

    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Resource usage:"), "{report}");
    assert!(
        report.contains("awk BEGIN"),
        "fixture descendant missing:\n{report}"
    );

    let user_cpu = resource_value(&report, "Aggregate user CPU: ", "ms");
    let system_cpu = resource_value(&report, "Aggregate system CPU: ", "ms");
    let peak_memory = resource_value(&report, "Peak aggregate resident memory: ", "KiB");

    assert!(
        user_cpu.is_some(),
        "user CPU should be available:\n{report}"
    );
    assert!(
        system_cpu.is_some(),
        "system CPU should be available:\n{report}"
    );
    assert!(
        peak_memory.is_some_and(|value| value > 0),
        "peak memory should be positive:\n{report}"
    );
}

#[test]
fn reports_filesystem_reads_and_separates_outside_paths() {
    let sandbox = TestDirectory::new("filesystem-read");
    let workdir = sandbox.path.join("workdir");
    fs::create_dir(&workdir).expect("working directory should be created");
    let inside = workdir.join("inside-input.txt");
    let outside = sandbox.path.join("outside-input.txt");
    fs::write(&inside, "inside filesystem input\n").expect("inside input should be written");
    fs::write(&outside, "outside filesystem input\n").expect("outside input should be written");

    let output = runlens_in(
        &workdir,
        &[
            "/bin/sh",
            "-c",
            "exec 3< \"$1\"; exec 4< \"$2\"; dd if=/proc/self/fd/3 of=/dev/null bs=1 count=8 status=none; dd if=/proc/self/fd/4 of=/dev/null bs=1 count=8 status=none; sleep 0.2",
            "filesystem-read-fixture",
            "inside-input.txt",
            outside.to_str().expect("outside path should be UTF-8"),
        ],
    );

    assert!(output.status.success());
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Filesystem activity:"), "{report}");
    assert!(report.contains("Inside working directory:"), "{report}");
    assert!(report.contains("Outside working directory:"), "{report}");
    assert!(report.contains("Read-capable files: 1"), "{report}");
    let inside_section = report
        .split("Inside working directory:")
        .nth(1)
        .and_then(|section| section.split("Outside working directory:").next())
        .expect("inside filesystem section should exist");
    let outside_section = report
        .split("Outside working directory:")
        .nth(1)
        .expect("outside filesystem section should exist");
    assert!(inside_section.contains(&inside.to_string_lossy().into_owned()));
    assert!(!inside_section.contains(&outside.to_string_lossy().into_owned()));
    assert!(outside_section.contains(&outside.to_string_lossy().into_owned()));
    assert!(!outside_section.contains(&inside.to_string_lossy().into_owned()));
    assert!(
        resource_value(&report, "Read bytes: ", "bytes").is_none_or(|bytes| bytes > 0),
        "read byte total should be positive or unavailable:\n{report}"
    );
    assert!(!report.contains("Read bytes: 0 bytes"), "{report}");
    assert!(
        !report.lines().any(|line| line.contains("Filesystem event")),
        "filesystem report should contain summaries, not raw events:\n{report}"
    );
}

#[test]
fn reports_filesystem_writes_and_byte_totals() {
    let sandbox = TestDirectory::new("filesystem-write");
    let workdir = sandbox.path.join("workdir");
    fs::create_dir(&workdir).expect("working directory should be created");
    let inside = workdir.join("inside-output.txt");
    let outside = sandbox.path.join("outside-output.txt");

    let output = runlens_in(
        &workdir,
        &[
            "/bin/sh",
            "-c",
            "exec 3> \"$1\"; exec 4> \"$2\"; printf inside-write >&3; printf outside-write >&4; sleep 0.2",
            "filesystem-write-fixture",
            "inside-output.txt",
            outside.to_str().expect("outside path should be UTF-8"),
        ],
    );

    assert!(output.status.success());
    assert_eq!(
        fs::read_to_string(&inside).expect("inside output should exist"),
        "inside-write"
    );
    assert_eq!(
        fs::read_to_string(&outside).expect("outside output should exist"),
        "outside-write"
    );

    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Inside working directory:"), "{report}");
    assert!(report.contains("Outside working directory:"), "{report}");
    assert!(report.contains("Write-capable files: 1"), "{report}");
    let inside_section = report
        .split("Inside working directory:")
        .nth(1)
        .and_then(|section| section.split("Outside working directory:").next())
        .expect("inside filesystem section should exist");
    let outside_section = report
        .split("Outside working directory:")
        .nth(1)
        .expect("outside filesystem section should exist");
    assert!(inside_section.contains(&inside.to_string_lossy().into_owned()));
    assert!(!inside_section.contains(&outside.to_string_lossy().into_owned()));
    assert!(outside_section.contains(&outside.to_string_lossy().into_owned()));
    assert!(!outside_section.contains(&inside.to_string_lossy().into_owned()));
    assert!(
        report.contains("Filesystem observation limits:"),
        "{report}"
    );
    assert!(
        resource_value(&report, "Write bytes: ", "bytes").is_none_or(|bytes| bytes > 0),
        "write byte total should be positive or unavailable:\n{report}"
    );
    assert!(!report.contains("Write bytes: 0 bytes"), "{report}");
}

#[test]
fn reports_survivor_and_preserves_primary_exit_without_killing_it() {
    let marker = std::env::temp_dir().join(format!("runlens-survivor-{}.pid", std::process::id()));
    let mut cleanup = SurvivorCleanup::new(marker.clone());
    let marker = marker.to_string_lossy().into_owned();
    let output = runlens(&[
        "/bin/sh",
        "-c",
        "sleep 30 >/dev/null 2>&1 & survivor=$!; printf '%s' \"$survivor\" > \"$1\"; sleep 0.1; exit 7",
        "runlens-survivor",
        &marker,
    ]);

    let pid = fs::read_to_string(&marker)
        .expect("survivor fixture should write its PID")
        .trim()
        .parse::<u32>()
        .expect("survivor PID should be numeric");
    cleanup.pid = Some(pid);

    assert_eq!(output.status.code(), Some(7));
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Surviving descendants: 1"), "{report}");
    assert!(report.contains(&format!("PID {pid}")), "{report}");
    assert!(process_is_alive(pid), "survivor should remain alive");
}

#[cfg(target_os = "linux")]
#[test]
fn reports_loopback_network_connection_without_payload_or_public_network() {
    let listener = LoopbackListener::new();
    let fixture = std::env::current_exe()
        .expect("test executable should be available")
        .to_string_lossy()
        .into_owned();
    let args = vec![
        fixture,
        "--exact".to_owned(),
        "network_fixture".to_owned(),
        "--nocapture".to_owned(),
    ];
    let output = runlens_with_env(
        &args,
        &[
            ("RUNLENS_NETWORK_FIXTURE_ADDR", listener.address.as_str()),
            ("RUNLENS_NETWORK_FIXTURE_HOLD_MILLIS", "1000"),
        ],
    );

    assert!(output.status.success());
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Network connections:"), "{report}");
    assert!(report.contains("Local connections: 1"), "{report}");
    assert!(report.contains("Remote connections: 0"), "{report}");
    assert!(report.contains("127.0.0.1:"), "{report}");
    assert!(report.contains(&listener.address), "{report}");
    assert!(
        !report.contains("runlens-network-payload-must-not-appear"),
        "network payload leaked into report:\n{report}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn reports_remote_network_activity_as_a_notable_finding() {
    let Some(listener) = LoopbackListener::non_loopback() else {
        return;
    };
    let fixture = std::env::current_exe()
        .expect("test executable should be available")
        .to_string_lossy()
        .into_owned();
    let args = vec![
        fixture,
        "--exact".to_owned(),
        "network_fixture".to_owned(),
        "--nocapture".to_owned(),
    ];
    let output = runlens_with_env(
        &args,
        &[
            ("RUNLENS_NETWORK_FIXTURE_ADDR", listener.address.as_str()),
            ("RUNLENS_NETWORK_FIXTURE_HOLD_MILLIS", "1000"),
        ],
    );

    assert!(output.status.success());
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Remote connections: 1"), "{report}");
    assert!(
        report.contains("remote/unexpected network activity"),
        "{report}"
    );
    assert!(report.contains(&listener.address), "{report}");
}

#[cfg(target_os = "linux")]
#[test]
fn reports_network_connection_for_surviving_process() {
    let listener = LoopbackListener::new();
    let marker = std::env::temp_dir().join(format!(
        "runlens-network-survivor-{}.pid",
        std::process::id()
    ));
    let mut cleanup = SurvivorCleanup::new(marker.clone());
    let fixture = std::env::current_exe()
        .expect("test executable should be available")
        .to_string_lossy()
        .into_owned();
    let marker = marker.to_string_lossy().into_owned();
    let args = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "\"$1\" --exact network_fixture --nocapture >/dev/null 2>&1 & sleep 0.5".to_owned(),
        "network-survivor".to_owned(),
        fixture,
    ];
    let output = runlens_with_env(
        &args,
        &[
            ("RUNLENS_NETWORK_FIXTURE_ADDR", listener.address.as_str()),
            ("RUNLENS_NETWORK_FIXTURE_PID_FILE", marker.as_str()),
            ("RUNLENS_NETWORK_FIXTURE_HOLD_MILLIS", "3000"),
        ],
    );

    let pid = fs::read_to_string(&marker)
        .expect("network survivor should write its PID")
        .trim()
        .parse::<u32>()
        .expect("network survivor PID should be numeric");
    cleanup.pid = Some(pid);

    assert!(output.status.success());
    assert!(
        process_is_alive(pid),
        "network survivor should remain alive"
    );
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    assert!(report.contains("Network connections:"), "{report}");
    assert!(report.contains(&listener.address), "{report}");
    assert!(report.contains(&format!("PID {pid}")), "{report}");
    let network_section = report
        .split("Network connections:")
        .nth(1)
        .and_then(|section| section.split("Process count:").next())
        .expect("network section should exist");
    assert!(
        network_section.contains(&format!("PID {pid} (surviving)")),
        "{network_section}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn reports_stable_sections_and_actionable_findings_for_complete_fixture() {
    let sandbox = TestDirectory::new("complete-report");
    let workdir = sandbox.path.join("workdir");
    let scan_directory = workdir.join("scan");
    let outside_directory = sandbox.path.join("outside");
    let sensitive_directory = outside_directory.join(".ssh");
    fs::create_dir_all(&scan_directory).expect("scan directory should be created");
    fs::create_dir_all(&sensitive_directory).expect("sensitive directory should be created");

    for index in 0..40 {
        fs::write(
            scan_directory.join(format!("input-{index:02}.txt")),
            b"scan fixture",
        )
        .expect("scan fixture input should be written");
    }
    let sensitive_path = sensitive_directory.join("credentials");
    fs::write(&sensitive_path, b"not-a-real-credential").expect("sensitive fixture should exist");
    let writable_path = workdir.join("fixture-output.txt");
    fs::write(&writable_path, b"output").expect("writable fixture should exist");

    let listener = LoopbackListener::new();
    let marker = sandbox.path.join("survivor.pid");
    let cleanup = SurvivorCleanup::new(marker.clone());
    let fixture = std::env::current_exe()
        .expect("test executable should be available")
        .to_string_lossy()
        .into_owned();
    let args = vec![
        fixture,
        "--exact".to_owned(),
        "complete_fixture".to_owned(),
        "--nocapture".to_owned(),
    ];
    let scan_directory = scan_directory.to_string_lossy().into_owned();
    let sensitive_path = sensitive_path.to_string_lossy().into_owned();
    let writable_path = writable_path.to_string_lossy().into_owned();
    let marker_path = marker.to_string_lossy().into_owned();
    let output = runlens_in_with_env(
        &workdir,
        &args,
        &[
            ("RUNLENS_COMPLETE_SCAN_DIRECTORY", scan_directory.as_str()),
            ("RUNLENS_COMPLETE_SENSITIVE_PATH", sensitive_path.as_str()),
            ("RUNLENS_COMPLETE_WRITABLE_PATH", writable_path.as_str()),
            (
                "RUNLENS_COMPLETE_NETWORK_ADDRESS",
                listener.address.as_str(),
            ),
            ("RUNLENS_COMPLETE_SURVIVOR_MARKER", marker_path.as_str()),
        ],
    );
    drop(cleanup);

    assert!(output.status.success());
    let report = String::from_utf8(output.stderr).expect("report should be UTF-8");
    for section in [
        "Command:",
        "Duration and resources:",
        "Processes:",
        "Filesystem:",
        "Network:",
        "Notable findings:",
    ] {
        assert!(report.contains(section), "missing {section} in:\n{report}");
    }
    assert!(report.contains("surviving descendant"), "{report}");
    assert!(report.contains("file/directory scanning"), "{report}");
    assert!(report.contains("outside working directory"), "{report}");
    assert!(report.contains("sensitive path"), "{report}");
    assert!(report.contains(".ssh/credentials"), "{report}");
    assert!(
        !report.contains("runlens-complete-fixture-payload-must-not-appear"),
        "network payload leaked into report:\n{report}"
    );
    assert!(
        !report.lines().any(|line| line.contains("Filesystem event")),
        "report should contain semantic summaries, not raw events:\n{report}"
    );
}

mod filesystem;
mod formatting;
mod network;
mod observation;
mod platform;
mod report;

use std::env;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, exit};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use formatting::format_command;
use observation::{LinuxObservationBoundary, ProcessObservation};
use report::ExecutionReport;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn getpid() -> c_int;
    fn signal(signal: c_int, handler: usize) -> usize;
}

#[cfg(target_os = "linux")]
const SIG_DFL: usize = 0;
#[cfg(target_os = "linux")]
const SIGNALS_TO_FORWARD: [c_int; 4] = [1, 2, 3, 15];
const OBSERVATION_INTERVAL: Duration = Duration::from_millis(50);

#[cfg(target_os = "linux")]
static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let Some(program) = args.first() else {
        eprintln!("usage: runlens <executable> [args...]");
        exit(2);
    };

    install_signal_handlers();
    let boundary = LinuxObservationBoundary;
    let mut child = match Command::new(program).args(&args[1..]).spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!(
                "runlens: failed to launch {:?}: {error} (launch failure; report not produced)",
                program
            );
            exit(1);
        }
    };
    let started = Instant::now();
    let mut observation = ProcessObservation::new(child.id(), env::current_dir().ok());
    observation.observe(&boundary, true);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                forward_pending_signal(child.id());
                observation.observe(&boundary, true);
                thread::sleep(OBSERVATION_INTERVAL);
            }
            Err(error) => {
                eprintln!("runlens: failed to wait for {:?}: {error}", program);
                exit(1);
            }
        }
    };
    let duration = started.elapsed();
    observation.observe(&boundary, false);

    let command = format_command(&args);
    let termination_signal = status_signal(&status);
    let report = ExecutionReport::new(
        command,
        duration,
        status.code(),
        termination_signal,
        observation,
    );
    report.render(&boundary);

    if let Some(signal) = termination_signal {
        terminate_with_signal(signal);
    }
    exit(status.code().unwrap_or(1));
}

#[cfg(target_os = "linux")]
extern "C" fn record_signal(signal: c_int) {
    let _ = RECEIVED_SIGNAL.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

#[cfg(not(target_os = "linux"))]
fn install_signal_handlers() {}

#[cfg(target_os = "linux")]
fn install_signal_handlers() {
    for signal_number in SIGNALS_TO_FORWARD {
        unsafe {
            signal(signal_number, record_signal as *const () as usize);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn forward_pending_signal(_child_pid: u32) {}

#[cfg(target_os = "linux")]
fn forward_pending_signal(child_pid: u32) {
    let signal_number = RECEIVED_SIGNAL.swap(0, Ordering::Relaxed);
    if signal_number == 0 {
        return;
    }

    let Ok(child_pid) = c_int::try_from(child_pid) else {
        return;
    };
    unsafe {
        let _ = kill(child_pid, signal_number);
    }
}

fn status_signal(status: &ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

#[cfg(target_os = "linux")]
fn terminate_with_signal(signal_number: i32) -> ! {
    let _ = std::io::stderr().flush();
    let signal_number = signal_number as c_int;
    unsafe {
        signal(signal_number, SIG_DFL);
        let _ = kill(getpid(), signal_number);
    }
    exit(128 + signal_number);
}

#[cfg(not(target_os = "linux"))]
fn terminate_with_signal(signal_number: i32) -> ! {
    exit(128 + signal_number);
}

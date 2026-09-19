use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const MAX_DETAIL_ITEMS: usize = 8;

pub(crate) fn print_path_samples(label: &str, paths: &[&PathBuf]) {
    eprintln!("{label}:");
    for path in paths.iter().take(MAX_DETAIL_ITEMS) {
        eprintln!("      - {}", sanitize_process_text(&path.to_string_lossy()));
    }
    if paths.len() > MAX_DETAIL_ITEMS {
        eprintln!("      - ... {} more", paths.len() - MAX_DETAIL_ITEMS);
    }
}

pub(crate) fn format_path_examples(paths: &[PathBuf]) -> String {
    let examples = paths
        .iter()
        .take(MAX_DETAIL_ITEMS)
        .map(|path| sanitize_process_text(&path.to_string_lossy()))
        .collect::<Vec<_>>();
    format_examples(&examples, paths.len())
}

pub(crate) fn format_examples(examples: &[String], total: usize) -> String {
    let mut result = examples.join(", ");
    if examples.len() < total {
        if !result.is_empty() {
            result.push_str(", ");
        }
        result.push_str(&format!("... {} more", total - examples.len()));
    }
    result
}

pub(crate) fn is_sensitive_path(path: &Path) -> bool {
    let text = path.to_string_lossy().to_ascii_lowercase();
    if text.starts_with("/etc/") || text.starts_with("/root/") {
        return true;
    }

    let sensitive_components = [".aws", ".config", ".gnupg", ".kube", ".ssh"];
    if path.components().any(|component| {
        let component = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        sensitive_components.contains(&component.as_str())
    }) {
        return true;
    }

    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "private_key",
    ]
    .iter()
    .any(|marker| text.contains(marker))
        || text.ends_with(".pem")
        || text.ends_with(".key")
}

pub(crate) fn pluralize<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    let milliseconds = duration.as_millis();
    if milliseconds < 1_000 {
        return format!("{milliseconds} ms");
    }

    let seconds = duration.as_secs();
    if seconds < 60 {
        return format!("{:.1} s", duration.as_secs_f64());
    }

    let minutes = seconds / 60;
    let seconds = seconds % 60;
    format!("{minutes} min {seconds} s")
}

pub(crate) fn format_command(arguments: &[impl AsRef<OsStr>]) -> String {
    arguments
        .iter()
        .map(|argument| format_argument(argument.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_argument(argument: &OsStr) -> String {
    let text = argument.to_string_lossy();
    if !text.is_empty()
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/:=+-".contains(character))
    {
        return text.into_owned();
    }

    format!("'{}'", text.replace('\'', "'\\''"))
}

pub(crate) fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        15 => "SIGTERM",
        _ => "signal",
    }
}

pub(crate) fn sanitize_process_text(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '\n' => ' ',
            '\r' => ' ',
            '\t' => ' ',
            character => character,
        })
        .collect()
}

# RunLens

RunLens is a Linux and macOS command wrapper that observes a command and its descendants, then prints a concise execution report.

The report can include:

- command, duration, and exit status;
- aggregate CPU usage and peak resident memory;
- process tree and surviving descendants;
- sampled filesystem activity and read/write totals;
- observed local and remote network connections; and
- notable findings such as outside-boundary activity, broad scans, network access, or leaked processes.

RunLens is local-only. It does not upload telemetry, capture network payloads, or automatically terminate surviving processes.

## Requirements

- Linux or macOS
- Rust and Cargo (stable toolchain)

## Installation

Install the CLI from crates.io:

```sh
cargo install runlens
```

To install the current checkout instead:

```sh
cargo install --path .
```

The package provides the `runlens` executable; it is currently a CLI package,
not a Rust library API.

## Usage

Run an executable directly and pass its arguments after it:

```sh
cargo run -- <executable> [args...]
```

Examples:

```sh
cargo run -- printf 'hello\n'
cargo run -- sh -c 'echo building; sleep 1'
```

The wrapped command keeps its normal standard input, output, and error streams. RunLens prints its report to standard error after the command finishes. The wrapped command's exit status is returned; a launch failure is reported separately.

To build and run the release binary:

```sh
cargo build --release
./target/release/runlens <executable> [args...]
```

Shell syntax is not interpreted implicitly. Invoke a shell explicitly when needed, for example `runlens sh -c 'command | other-command'`.

## Report notes

The filesystem boundary defaults to RunLens's current working directory. Observation uses `/proc` on Linux and native process metadata on macOS. Both backends are best-effort:

- short-lived activity or inaccessible process metadata may be missed;
- macOS permissions may restrict process, file descriptor, or socket metadata;
- filesystem paths are sampled from open descriptors and do not prove a completed operation;
- byte totals are aggregate kernel-reported storage I/O and are not path-specific;
- network payloads are never captured; and
- surviving descendants are reported but not cleaned up.

Unavailable measurements are labeled as unavailable or limited rather than reported as zero.

## Development

Format, check, lint, and test the project with:

```sh
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

The CLI suite in `tests/cli.rs` includes Linux- and macOS-specific cases. Run it on each platform to exercise that platform's native observation backend.

## Scope

This is the RunLens MVP. It supports best-effort process, resource, filesystem, and network observation on Linux and macOS. It intentionally does not provide a dashboard, cloud service, persistent run history, raw syscall or packet output, or automatic remediation.

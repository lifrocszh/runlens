use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::formatting::{MAX_DETAIL_ITEMS, sanitize_process_text};
use crate::observation::{ObservationBoundary, ProcessInfo};

pub(crate) struct NetworkObservation {
    connections: BTreeMap<NetworkConnectionKey, NetworkConnection>,
    backend_available: bool,
    observation_limited: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SocketProtocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl SocketProtocol {
    fn table(self) -> (&'static str, bool) {
        match self {
            Self::Tcp => ("tcp", false),
            Self::Tcp6 => ("tcp6", true),
            Self::Udp => ("udp", false),
            Self::Udp6 => ("udp6", true),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Tcp | Self::Tcp6 => "TCP",
            Self::Udp | Self::Udp6 => "UDP",
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NetworkEndpoint {
    address: String,
    port: u16,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NetworkConnectionKey {
    protocol: SocketProtocol,
    local: NetworkEndpoint,
    remote: NetworkEndpoint,
}

pub(crate) struct NetworkConnection {
    key: NetworkConnectionKey,
    pub(crate) state: String,
    pub(crate) processes: BTreeMap<u32, String>,
}

pub(crate) struct SocketRecord {
    key: NetworkConnectionKey,
    state: String,
}

impl NetworkObservation {
    pub(crate) fn new() -> Self {
        Self {
            connections: BTreeMap::new(),
            backend_available: false,
            observation_limited: false,
        }
    }

    pub(crate) fn observe<B: ObservationBoundary>(
        &mut self,
        boundary: &B,
        processes: &HashMap<u32, ProcessInfo>,
        current_tree: &HashSet<u32>,
    ) {
        self.observe_pids(boundary, processes, current_tree.iter().copied());
    }

    pub(crate) fn observe_pids<B: ObservationBoundary, I>(
        &mut self,
        boundary: &B,
        processes: &HashMap<u32, ProcessInfo>,
        pids: I,
    ) where
        I: IntoIterator<Item = u32>,
    {
        for pid in pids {
            let Some(info) = processes.get(&pid) else {
                continue;
            };
            if info.is_alive() {
                self.observe_process(boundary, pid, info);
            }
        }
    }

    fn observe_process<B: ObservationBoundary>(
        &mut self,
        boundary: &B,
        pid: u32,
        info: &ProcessInfo,
    ) {
        let Some(snapshot) = boundary.network_snapshot(pid) else {
            self.observation_limited = true;
            return;
        };
        self.backend_available = true;
        self.observation_limited |= snapshot.limited;

        for inode in snapshot.inodes {
            let Some(socket) = snapshot.sockets.get(&inode) else {
                continue;
            };
            let connection = self
                .connections
                .entry(socket.key.clone())
                .or_insert_with(|| NetworkConnection {
                    key: socket.key.clone(),
                    state: socket.state.clone(),
                    processes: BTreeMap::new(),
                });
            connection.state.clone_from(&socket.state);
            connection.processes.insert(pid, info.command.clone());
        }
    }

    pub(crate) fn print_report(
        &self,
        processes: &HashMap<u32, ProcessInfo>,
        process_snapshot_available: bool,
    ) {
        if !self.backend_available {
            eprintln!("  Network connections: unavailable");
            eprintln!(
                "  Network observation limits: Linux /proc network metadata was unavailable; payloads are not captured."
            );
            return;
        }

        if self.connections.is_empty() {
            eprintln!("  Network connections: none observed");
        } else {
            let remote_count = self
                .connections
                .values()
                .filter(|connection| connection.key.is_remote())
                .count();
            let local_count = self.connections.len() - remote_count;
            eprintln!("  Network connections:");
            eprintln!("    Connection count: {}", self.connections.len());
            eprintln!("    Local connections: {local_count}");
            eprintln!("    Remote connections: {remote_count}");
            for connection in self.connections.values().take(MAX_DETAIL_ITEMS) {
                let classification = if connection.key.is_remote() {
                    "remote connection"
                } else {
                    "local connection"
                };
                eprintln!(
                    "    - {} local {} -> remote {} ({}; {classification})",
                    connection.key.protocol.label(),
                    format_network_endpoint(&connection.key.local),
                    format_network_endpoint(&connection.key.remote),
                    connection.state,
                );
                let associated_processes = connection
                    .processes
                    .iter()
                    .map(|(pid, command)| {
                        let status = if !process_snapshot_available {
                            " (survivor status unavailable)"
                        } else if processes.get(pid).is_some_and(ProcessInfo::is_alive) {
                            " (surviving)"
                        } else {
                            ""
                        };
                        format!("PID {pid}{status}: {}", sanitize_process_text(command))
                    })
                    .collect::<Vec<_>>();
                if !associated_processes.is_empty() {
                    eprintln!(
                        "      Associated processes: {}",
                        associated_processes.join(", ")
                    );
                }
            }
        }

        let limits = if self.observation_limited {
            "endpoints are sampled from process socket descriptors and /proc network tables; short-lived sockets or restricted processes may be missed; payloads are not captured."
        } else {
            "endpoints are sampled from process socket descriptors and /proc network tables; short-lived sockets may be missed; payloads are not captured."
        };
        eprintln!("  Network observation limits: {limits}");
    }

    pub(crate) fn remote_connections(&self) -> Vec<&NetworkConnection> {
        self.connections
            .values()
            .filter(|connection| connection.key.is_remote())
            .collect()
    }

    pub(crate) fn is_limited(&self) -> bool {
        !self.backend_available || self.observation_limited
    }
}

impl NetworkConnection {
    pub(crate) fn protocol_label(&self) -> &'static str {
        self.key.protocol.label()
    }

    pub(crate) fn remote_endpoint(&self) -> String {
        format_network_endpoint(&self.key.remote)
    }
}

impl NetworkConnectionKey {
    fn is_remote(&self) -> bool {
        is_remote_address(&self.remote.address)
    }
}

pub(crate) fn read_socket_inodes(pid: u32) -> Option<(HashSet<u64>, bool)> {
    let entries = fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut inodes = HashSet::new();
    let mut limited = false;
    for entry in entries {
        let Ok(entry) = entry else {
            limited = true;
            continue;
        };
        let Ok(target) = fs::read_link(entry.path()) else {
            limited = true;
            continue;
        };
        let Some(inode) = target
            .to_str()
            .and_then(|target| target.strip_prefix("socket:["))
            .and_then(|target| target.strip_suffix(']'))
            .and_then(|inode| inode.parse().ok())
        else {
            continue;
        };
        inodes.insert(inode);
    }
    Some((inodes, limited))
}

pub(crate) fn read_network_sockets(pid: u32) -> Option<(HashMap<u64, SocketRecord>, bool)> {
    let protocols = [
        SocketProtocol::Tcp,
        SocketProtocol::Tcp6,
        SocketProtocol::Udp,
        SocketProtocol::Udp6,
    ];
    let mut sockets = HashMap::new();
    let mut read_any = false;
    let mut limited = false;

    for protocol in protocols {
        let (table, ipv6) = protocol.table();
        let Ok(contents) = fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            limited = true;
            continue;
        };
        read_any = true;
        for line in contents.lines().skip(1) {
            let Some((inode, socket)) = parse_network_socket(line, protocol, ipv6) else {
                limited = true;
                continue;
            };
            sockets.insert(inode, socket);
        }
    }

    read_any.then_some((sockets, limited))
}

fn parse_network_socket(
    line: &str,
    protocol: SocketProtocol,
    ipv6: bool,
) -> Option<(u64, SocketRecord)> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let local = parse_network_endpoint(fields.get(1)?, ipv6)?;
    let remote = parse_network_endpoint(fields.get(2)?, ipv6)?;
    let state = network_socket_state(protocol, fields.get(3)?)?;
    let inode = fields.get(9)?.parse().ok()?;
    let key = NetworkConnectionKey {
        protocol,
        local,
        remote,
    };
    Some((inode, SocketRecord { key, state }))
}

fn parse_network_endpoint(value: &str, ipv6: bool) -> Option<NetworkEndpoint> {
    let (address, port) = value.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let address = if ipv6 {
        decode_ipv6_address(address)?
    } else {
        decode_ipv4_address(address)?
    };
    Some(NetworkEndpoint { address, port })
}

fn decode_ipv4_address(value: &str) -> Option<String> {
    if value.len() != 8 {
        return None;
    }
    let address = u32::from_str_radix(value, 16).ok()?.to_le_bytes();
    Some(Ipv4Addr::from(address).to_string())
}

fn decode_ipv6_address(value: &str) -> Option<String> {
    if value.len() != 32 {
        return None;
    }
    let mut address = [0_u8; 16];
    for (index, byte) in address.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    address[0..4].reverse();
    address[4..8].reverse();
    address[8..12].reverse();
    address[12..16].reverse();
    Some(Ipv6Addr::from(address).to_string())
}

fn network_socket_state(protocol: SocketProtocol, value: &str) -> Option<String> {
    let state = u8::from_str_radix(value, 16).ok()?;
    let name = match protocol {
        SocketProtocol::Tcp | SocketProtocol::Tcp6 => match state {
            0x01 => "ESTABLISHED",
            0x02 => "SYN_SENT",
            0x03 => "SYN_RECV",
            0x04 => "FIN_WAIT1",
            0x05 => "FIN_WAIT2",
            0x06 => "TIME_WAIT",
            0x07 => "CLOSE",
            0x08 => "CLOSE_WAIT",
            0x09 => "LAST_ACK",
            0x0A => "LISTEN",
            0x0B => "CLOSING",
            0x0C => "NEW_SYN_RECV",
            _ => return Some(format!("0x{state:02X}")),
        },
        SocketProtocol::Udp | SocketProtocol::Udp6 => match state {
            0x01 => "ESTABLISHED",
            0x07 => "UNCONNECTED",
            _ => return Some(format!("0x{state:02X}")),
        },
    };
    Some(name.to_owned())
}

fn format_network_endpoint(endpoint: &NetworkEndpoint) -> String {
    if endpoint.address.contains(':') {
        format!("[{}]:{}", endpoint.address, endpoint.port)
    } else {
        format!("{}:{}", endpoint.address, endpoint.port)
    }
}

fn is_remote_address(address: &str) -> bool {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => !address.is_loopback() && !address.is_unspecified(),
        Ok(IpAddr::V6(address)) => !address.is_loopback() && !address.is_unspecified(),
        Err(_) => true,
    }
}

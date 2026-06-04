//! SOCK_DIAG netlink socket lookup.
//!
//! Queries the kernel's socket table via `SOCK_DIAG` / `inet_diag`, returning
//! `(inode, uid)` synchronously from kernel data structures. This avoids the
//! TOCTOU race where `/proc/net/tcp` is not yet updated when NFQUEUE delivers
//! the first SYN of a new connection.

use std::net::IpAddr;

use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_sock_diag::constants::{AF_INET, AF_INET6};
use netlink_packet_sock_diag::inet::{ExtensionFlags, InetRequest, SocketId, StateFlags};
use netlink_packet_sock_diag::message::SockDiagMessage;
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

use core_types::TransportProtocol;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Query the kernel for a socket matching `(src_ip, src_port)`.
///
/// Returns `(inode, uid)` on success. `None` if the socket does not exist,
/// netlink is unavailable, or the lookup fails.
///
/// **Dual-family query:** Many applications use `AF_INET6` sockets with
/// `IPV6_V6ONLY=0` even for IPv4 destinations. The kernel records these in
/// the IPv6 socket table as `::ffff:a.b.c.d`. Querying only `AF_INET` for an
/// IPv4 source address misses these entries. We query both families and return
/// the first match.
///
/// **UDP wildcard retry:** UDP sockets often bind to `0.0.0.0` (INADDR_ANY)
/// rather than a specific source IP. If the specific-IP query returns nothing
/// for UDP, we retry with the wildcard address.
pub fn query_socket_inode(
    src_ip: IpAddr,
    src_port: u16,
    protocol: TransportProtocol,
) -> Option<(u64, u32)> {
    let ipproto = if matches!(protocol, TransportProtocol::Udp | TransportProtocol::Quic) {
        IPPROTO_UDP
    } else {
        IPPROTO_TCP
    };

    // Build the ordered list of (family, source_address) to try.
    // Primary family first, then the other family (handles AF_INET6 sockets
    // used for IPv4 connections via ::ffff: mapped addresses).
    let families: [(u8, IpAddr); 2] = match src_ip {
        IpAddr::V4(v4) => [
            (AF_INET, IpAddr::V4(v4)),
            (AF_INET6, IpAddr::V6(v4.to_ipv6_mapped())),
        ],
        IpAddr::V6(v6) => [
            (AF_INET6, IpAddr::V6(v6)),
            // For IPv6 source, also try AF_INET in case it's an IPv4-mapped
            // address that the kernel stores in the IPv4 table.
            (AF_INET, v6.to_ipv4_mapped().map_or(src_ip, IpAddr::V4)),
        ],
    };

    for &(family, query_ip) in &families {
        if let Some(result) = query_single_family(family, query_ip, src_port, ipproto) {
            return Some(result);
        }
    }

    // UDP wildcard retry: if the specific-IP queries failed for UDP, try
    // querying with INADDR_ANY (0.0.0.0) as the source address. This handles
    // sockets that bind to the wildcard address but send from a real IP.
    if matches!(protocol, TransportProtocol::Udp | TransportProtocol::Quic) {
        let wildcard_ip = match src_ip {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        // Try both families for the wildcard too.
        let wildcard_families: [(u8, IpAddr); 2] = match src_ip {
            IpAddr::V4(_) => [
                (AF_INET, wildcard_ip),
                (
                    AF_INET6,
                    IpAddr::V6(std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()),
                ),
            ],
            IpAddr::V6(_) => [
                (AF_INET6, wildcard_ip),
                (AF_INET, IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            ],
        };
        for &(family, query_ip) in &wildcard_families {
            if let Some(result) = query_single_family(family, query_ip, src_port, ipproto) {
                return Some(result);
            }
        }
    }

    None
}

/// Send a single SOCK_DIAG netlink query for one (family, source_address) pair.
fn query_single_family(
    family: u8,
    query_ip: IpAddr,
    src_port: u16,
    ipproto: u8,
) -> Option<(u64, u32)> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG).ok()?;
    socket.bind(&SocketAddr::new(0, 0)).ok()?;
    let kernel_addr = SocketAddr::new(0, 0);
    socket.connect(&kernel_addr).ok()?;

    let request = InetRequest {
        family,
        protocol: ipproto,
        extensions: ExtensionFlags::empty(),
        states: StateFlags::all(),
        socket_id: SocketId {
            source_port: src_port,
            destination_port: 0,
            source_address: query_ip,
            destination_address: wildcard_dest_addr(query_ip),
            interface_id: 0,
            cookie: [0u8; 8],
        },
    };

    let mut msg = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::from(SockDiagMessage::InetRequest(request)),
    );
    msg.header.flags = NLM_F_REQUEST;
    msg.header.sequence_number = 1;
    msg.finalize();

    let mut buf = vec![0u8; msg.buffer_len()];
    msg.serialize(&mut buf);

    socket.send(&buf[..], 0).ok()?;

    // Read until we get a matching inet_diag response or an error/done.
    for _ in 0..16 {
        let data = socket.recv_from_full().ok()?.0;
        let response = NetlinkMessage::<SockDiagMessage>::deserialize(&data).ok()?;

        match response.payload {
            NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(resp)) => {
                let h = &resp.header;
                if h.inode == 0 {
                    continue;
                }
                if h.socket_id.source_port != src_port {
                    continue;
                }
                // The response address might be IPv4-mapped IPv6; normalize
                // before comparing to the original query address.
                if !sock_addr_matches(h.socket_id.source_address, query_ip) {
                    continue;
                }
                return Some((h.inode as u64, h.uid));
            }
            NetlinkPayload::Error(_) => {
                return None;
            }
            NetlinkPayload::Noop | NetlinkPayload::Overrun(_) => return None,
            _ => continue,
        }
    }

    None
}

fn wildcard_dest_addr(src_ip: IpAddr) -> IpAddr {
    match src_ip {
        IpAddr::V4(_) => IpAddr::from([0u8; 4]),
        IpAddr::V6(_) => IpAddr::from([0u8; 16]),
    }
}

/// Match source addresses, treating IPv4-mapped IPv6 as equivalent to IPv4.
fn sock_addr_matches(sock_addr: IpAddr, query: IpAddr) -> bool {
    match (normalize_ip(sock_addr), normalize_ip(query)) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a == b,
        (IpAddr::V6(a), IpAddr::V6(b)) => a == b,
        _ => false,
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_socket_inode_does_not_panic() {
        let _ = query_socket_inode(IpAddr::from([192, 0, 2, 1]), 62934, TransportProtocol::Tcp);
    }

    #[test]
    fn sock_addr_matches_ipv4_mapped() {
        let v4: IpAddr = "10.0.2.15".parse().unwrap();
        let mapped: IpAddr = "::ffff:10.0.2.15".parse().unwrap();
        assert!(sock_addr_matches(mapped, v4));
        assert!(sock_addr_matches(v4, mapped));
    }
}

//! Integration test for the DNS responder over REAL UDP + TCP sockets (SPEC §3).
//!
//! Binds `serve_dns` on an ephemeral loopback high port (no privilege / no `:53` needed),
//! then sends real DNS queries and asserts the wire response: an `A` query for `x.dig` returns
//! `127.0.0.5`, a non-`.dig` name is `REFUSED`, and the SAME query answers identically over
//! TCP (length-prefixed). This is the automatable form of the SPEC's `dig @127.0.0.5 -p 53`
//! check (which needs BIND tools + the configured loopback IP).

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use dig_dns::server::{bind_dns, serve_dns};

const SERVED_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

/// Build a minimal DNS `A` query for `name` (id 0xABCD, RD set).
fn a_query(name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&[0xAB, 0xCD]); // id
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar = 0
    for label in name.split('.').filter(|l| !l.is_empty()) {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0); // root
    m.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    m
}

fn rcode(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[2], resp[3]]) & 0xF
}
fn ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

#[tokio::test]
async fn dns_responder_answers_over_udp_and_tcp() {
    // Bind the responder on an ephemeral loopback port (127.0.0.1:0), on both UDP + TCP.
    let (udp, tcp) = bind_dns(Ipv4Addr::LOCALHOST, 0).await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp_addr = tcp.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        serve_dns(udp, tcp, SERVED_IP, "dig".to_string(), 2, async {
            let _ = rx.await;
        })
        .await;
    });

    // --- UDP: A x.dig → 127.0.0.5 ----------------------------------------------------------
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();
    client.send(&a_query("x.dig")).await.unwrap();
    let mut buf = [0u8; 1500];
    let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .expect("udp response timed out")
        .unwrap();
    let resp = &buf[..n];
    assert_eq!(&resp[0..2], &[0xAB, 0xCD], "echoed id");
    assert_eq!(rcode(resp), 0, "NOERROR");
    assert_eq!(ancount(resp), 1, "one A answer");
    assert_eq!(
        &resp[resp.len() - 4..],
        &[127, 0, 0, 5],
        "A rdata = 127.0.0.5"
    );

    // --- UDP: a non-.dig name → REFUSED ----------------------------------------------------
    client.send(&a_query("example.com")).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
        .await
        .expect("udp response timed out")
        .unwrap();
    assert_eq!(rcode(&buf[..n]), 5, "REFUSED for a non-.dig name");
    assert_eq!(ancount(&buf[..n]), 0);

    // --- TCP: same A x.dig, length-prefixed ------------------------------------------------
    let mut stream = TcpStream::connect(tcp_addr).await.unwrap();
    let query = a_query("x.dig");
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&query).await.unwrap();
    stream.flush().await.unwrap();

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.unwrap();
    let rlen = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; rlen];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(rcode(&resp), 0);
    assert_eq!(ancount(&resp), 1);
    assert_eq!(
        &resp[resp.len() - 4..],
        &[127, 0, 0, 5],
        "TCP answer matches UDP"
    );

    let _ = tx.send(());
}

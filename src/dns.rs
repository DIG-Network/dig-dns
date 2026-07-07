//! The DNS responder wire codec + answering policy (SPEC §3).
//!
//! `dig-dns` answers `*.<tld>` (and the bare apex `<tld>`) with `A <loopback_ip>` and refuses
//! everything else — it is authoritative ONLY for the browsable TLD, never a recursive
//! resolver. This module is PURE: it parses a DNS query and builds the response bytes; the
//! UDP/TCP socket glue lives in [`crate::server`] and is exercised by an integration test.
//!
//! The codec is hand-rolled (rather than a full DNS library) because the answering policy is a
//! constant-time wildcard — a fixed `A` record, or `NODATA`/`REFUSED` — so a ~single-question
//! parser + a compression-pointer answer is all that is needed, and it stays dependency-light
//! and byte-level unit-testable.
//!
//! Policy (SPEC §3):
//! - `<label>.<tld>` / apex `<tld>`, type **A** → `A <loopback_ip>`, short TTL, `AA=1`.
//! - any `*.<tld>`, type **AAAA** or any other type → **NODATA** (`NOERROR`, empty answer).
//! - any name NOT under `.<tld>` → **REFUSED**.
//! - **EDNS0** OPT is echoed; on a UDP response exceeding the negotiated payload size the
//!   **TC** bit is set so the client retries over TCP (which has no size limit).
//! - the queried name's exact case is preserved in the echoed question (DNS 0x20).

use std::net::Ipv4Addr;

/// DNS record type `A` (IPv4 address).
const TYPE_A: u16 = 1;
/// DNS record type `OPT` (EDNS0 pseudo-record).
const TYPE_OPT: u16 = 41;
/// RCODE `NOERROR`.
const RCODE_NOERROR: u16 = 0;
/// RCODE `FORMERR` (the query could not be parsed).
const RCODE_FORMERR: u16 = 1;
/// RCODE `REFUSED` (not authoritative for this name).
const RCODE_REFUSED: u16 = 5;
/// The classic (non-EDNS) UDP payload limit; a larger response sets TC.
const DEFAULT_UDP_MAX: usize = 512;
/// The fixed DNS header length; the first question always begins here.
const HEADER_LEN: usize = 12;

/// Which transport a response is being built for — UDP applies the payload-size/TC rule; TCP
/// has no size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A UDP query (TC applies when the response exceeds the negotiated payload size).
    Udp,
    /// A TCP query (no size limit; the socket layer length-prefixes the message).
    Tcp,
}

/// A parsed DNS query — only the fields the policy needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Query {
    /// The 16-bit query id (echoed).
    id: [u8; 2],
    /// The opcode + RD bit from the request flags (echoed).
    opcode: u16,
    /// Recursion-Desired bit (echoed).
    rd: bool,
    /// The question's labels, decoded (for the TLD test); case as sent.
    labels: Vec<Vec<u8>>,
    /// The query type.
    qtype: u16,
    /// The raw question bytes (name + qtype + qclass) — echoed verbatim to preserve 0x20 case.
    raw_question: Vec<u8>,
    /// The requestor's EDNS0 UDP payload size, if an OPT record was present.
    edns_udp_size: Option<u16>,
}

/// The answer decision for a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Serve one `A <loopback_ip>` record.
    A,
    /// `NOERROR` with no answer (right name, no data of this type).
    NoData,
    /// `REFUSED` — not under the served TLD.
    Refused,
}

/// Build a DNS response for `request`, or `None` when the request is too short to carry an id
/// (nothing to reply to). `loopback_ip` is the address served; `tld` the browsable TLD; `ttl`
/// the answer TTL (seconds). For [`Transport::Udp`], the TC bit is set (and answers dropped)
/// when the response would exceed the negotiated payload size.
pub fn respond(
    request: &[u8],
    loopback_ip: Ipv4Addr,
    tld: &str,
    ttl: u32,
    transport: Transport,
) -> Option<Vec<u8>> {
    if request.len() < HEADER_LEN {
        return None; // no id → cannot form a reply
    }
    match parse(request) {
        Ok(query) => Some(build(&query, loopback_ip, tld, ttl, transport)),
        // A malformed question still has an id/header → reply FORMERR (echo no question).
        Err(()) => Some(build_formerr(request)),
    }
}

/// Parse the header + first question (+ optional EDNS OPT).
fn parse(msg: &[u8]) -> Result<Query, ()> {
    let id = [msg[0], msg[1]];
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let opcode = (flags >> 11) & 0xF;
    let rd = (flags & 0x0100) != 0;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let arcount = u16::from_be_bytes([msg[10], msg[11]]);
    if qdcount == 0 {
        return Err(());
    }

    // Read the question name (uncompressed labels, terminated by a zero byte).
    let mut pos = HEADER_LEN;
    let mut labels: Vec<Vec<u8>> = Vec::new();
    loop {
        let len = *msg.get(pos).ok_or(())? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // A compression pointer has no place in a question name.
        if len & 0xC0 != 0 {
            return Err(());
        }
        let start = pos + 1;
        let end = start + len;
        let label = msg.get(start..end).ok_or(())?.to_vec();
        labels.push(label);
        pos = end;
    }
    // qtype (2) + qclass (2).
    let qtype = u16::from_be_bytes([*msg.get(pos).ok_or(())?, *msg.get(pos + 1).ok_or(())?]);
    let q_end = pos + 4;
    if q_end > msg.len() {
        return Err(());
    }
    let raw_question = msg[HEADER_LEN..q_end].to_vec();

    // Best-effort EDNS0 detection: in a QUERY the additional section (if any) carries the OPT
    // record as `root-name(0x00) TYPE=41 CLASS=udp_size …`.
    let edns_udp_size = if arcount >= 1 {
        parse_opt_udp_size(msg, q_end)
    } else {
        None
    };

    Ok(Query {
        id,
        opcode,
        rd,
        labels,
        qtype,
        raw_question,
        edns_udp_size,
    })
}

/// Read the EDNS0 OPT record's advertised UDP payload size, if the additional section begins
/// with a root-named OPT record at `pos`.
fn parse_opt_udp_size(msg: &[u8], pos: usize) -> Option<u16> {
    // root name (1 byte 0x00) + type (2) + class (2) = 5 bytes minimum.
    if msg.get(pos)? != &0x00 {
        return None;
    }
    let rtype = u16::from_be_bytes([*msg.get(pos + 1)?, *msg.get(pos + 2)?]);
    if rtype != TYPE_OPT {
        return None;
    }
    Some(u16::from_be_bytes([*msg.get(pos + 3)?, *msg.get(pos + 4)?]))
}

/// Decide the answer for a query name + type.
fn decide(labels: &[Vec<u8>], qtype: u16, tld: &str) -> Answer {
    let under_tld = labels
        .last()
        .map(|l| l.eq_ignore_ascii_case(tld.as_bytes()))
        .unwrap_or(false);
    if !under_tld {
        Answer::Refused
    } else if qtype == TYPE_A {
        Answer::A
    } else {
        Answer::NoData
    }
}

/// Build the response bytes for a parsed query.
fn build(
    query: &Query,
    loopback_ip: Ipv4Addr,
    tld: &str,
    ttl: u32,
    transport: Transport,
) -> Vec<u8> {
    let answer = decide(&query.labels, query.qtype, tld);
    let under_tld = answer != Answer::Refused;
    let rcode = if matches!(answer, Answer::Refused) {
        RCODE_REFUSED
    } else {
        RCODE_NOERROR
    };
    let has_opt = query.edns_udp_size.is_some();
    let ancount: u16 = if matches!(answer, Answer::A) { 1 } else { 0 };

    // Assemble the answer + additional sections first, so we can size-check for UDP TC.
    let mut answers = Vec::new();
    if matches!(answer, Answer::A) {
        write_a_answer(&mut answers, ttl, loopback_ip);
    }
    let mut additional = Vec::new();
    if has_opt {
        write_opt(&mut additional);
    }

    let full_len = HEADER_LEN + query.raw_question.len() + answers.len() + additional.len();
    // UDP payload limit: the EDNS-advertised size, else the classic 512.
    let truncate = matches!(transport, Transport::Udp)
        && full_len
            > query
                .edns_udp_size
                .map(usize::from)
                .unwrap_or(DEFAULT_UDP_MAX);

    let mut out = Vec::with_capacity(full_len);
    out.extend_from_slice(&query.id);
    let (final_an, tc) = if truncate {
        (0u16, true)
    } else {
        (ancount, false)
    };
    out.extend_from_slice(&response_flags(
        query.opcode,
        under_tld,
        tc,
        query.rd,
        rcode,
    ));
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount (echo the question)
    out.extend_from_slice(&final_an.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&(has_opt as u16).to_be_bytes()); // arcount (OPT still echoed)
    out.extend_from_slice(&query.raw_question);
    if !truncate {
        out.extend_from_slice(&answers);
    }
    out.extend_from_slice(&additional);
    out
}

/// Build a `FORMERR` response echoing only the request's id/opcode/RD (no question).
fn build_formerr(request: &[u8]) -> Vec<u8> {
    let flags = u16::from_be_bytes([request[2], request[3]]);
    let opcode = (flags >> 11) & 0xF;
    let rd = (flags & 0x0100) != 0;
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&request[0..2]); // id
    out.extend_from_slice(&response_flags(opcode, false, false, rd, RCODE_FORMERR));
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // qd/an/ns/ar = 0
    out
}

/// Compose the 2-byte response flags: `QR=1`, echoed opcode, `AA` for our TLD, optional `TC`,
/// echoed `RD`, `RA=0`, and the rcode.
fn response_flags(opcode: u16, aa: bool, tc: bool, rd: bool, rcode: u16) -> [u8; 2] {
    let mut flags: u16 = 0x8000; // QR
    flags |= (opcode & 0xF) << 11;
    if aa {
        flags |= 0x0400;
    }
    if tc {
        flags |= 0x0200;
    }
    if rd {
        flags |= 0x0100;
    }
    flags |= rcode & 0xF;
    flags.to_be_bytes()
}

/// Append an `A` answer that points (via compression) at the question name at offset 12.
fn write_a_answer(out: &mut Vec<u8>, ttl: u32, ip: Ipv4Addr) {
    out.extend_from_slice(&[0xC0, 0x0C]); // name = pointer to offset 12 (the question)
    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    out.extend_from_slice(&ip.octets());
}

/// Append an echoed EDNS0 OPT record (root name, our payload size, version 0, no options).
fn write_opt(out: &mut Vec<u8>) {
    out.push(0x00); // root name
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&4096u16.to_be_bytes()); // our advertised UDP payload size (class)
    out.extend_from_slice(&[0, 0, 0, 0]); // ttl: ext-rcode 0, version 0, flags 0
    out.extend_from_slice(&0u16.to_be_bytes()); // rdlength 0
}

// --- Client-side helpers (used by `doctor`'s direct-DNS probe) ------------------------------

/// Build a standard DNS query (id `0x0000`, RD set, one question) for `name` + `A`. Encodes each
/// dot-separated label; no EDNS. Used to probe the responder directly.
pub fn build_a_query(name: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&[0x00, 0x00]); // id
    m.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar = 0
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let len = label.len().min(63) as u8;
        m.push(len);
        m.extend_from_slice(&label.as_bytes()[..len as usize]);
    }
    m.push(0); // root
    m.extend_from_slice(&TYPE_A.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    m
}

/// Advance past a DNS name at `pos`, returning the position after it. A compression pointer
/// (top two bits set) is two bytes; otherwise it is length-prefixed labels ending in a zero.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(pos + 2); // compression pointer
        }
        pos += 1 + len;
    }
}

/// Parse the FIRST `A` record's IPv4 address from a DNS RESPONSE, walking past the questions and
/// answer names (compression-aware). Returns `None` when there is no `A` answer.
pub fn parse_first_a_ipv4(response: &[u8]) -> Option<Ipv4Addr> {
    if response.len() < HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]);
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let mut pos = HEADER_LEN;
    // Skip the questions (name + qtype(2) + qclass(2)).
    for _ in 0..qdcount {
        pos = skip_name(response, pos)?;
        pos += 4;
    }
    // Walk the answers.
    for _ in 0..ancount {
        pos = skip_name(response, pos)?;
        let rtype = u16::from_be_bytes([*response.get(pos)?, *response.get(pos + 1)?]);
        let rdlength =
            u16::from_be_bytes([*response.get(pos + 8)?, *response.get(pos + 9)?]) as usize;
        let rdata_start = pos + 10;
        if rtype == TYPE_A && rdlength == 4 {
            let b = response.get(rdata_start..rdata_start + 4)?;
            return Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
        }
        pos = rdata_start + rdlength;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 5);

    /// Build a minimal DNS query for `name` + `qtype` (id 0x1234, RD set), optionally with an
    /// EDNS OPT advertising `edns_size`.
    fn query(name: &str, qtype: u16, edns_size: Option<u16>) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&0u16.to_be_bytes()); // ancount
        m.extend_from_slice(&0u16.to_be_bytes()); // nscount
        m.extend_from_slice(&(edns_size.is_some() as u16).to_be_bytes()); // arcount
        for label in name.split('.').filter(|l| !l.is_empty()) {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0); // root
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        if let Some(size) = edns_size {
            m.push(0x00); // OPT root name
            m.extend_from_slice(&TYPE_OPT.to_be_bytes());
            m.extend_from_slice(&size.to_be_bytes()); // class = udp size
            m.extend_from_slice(&[0, 0, 0, 0]); // ttl
            m.extend_from_slice(&0u16.to_be_bytes()); // rdlength
        }
        m
    }

    fn flags(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[2], resp[3]])
    }
    fn rcode(resp: &[u8]) -> u16 {
        flags(resp) & 0xF
    }
    fn qr(resp: &[u8]) -> bool {
        flags(resp) & 0x8000 != 0
    }
    fn aa(resp: &[u8]) -> bool {
        flags(resp) & 0x0400 != 0
    }
    fn tc(resp: &[u8]) -> bool {
        flags(resp) & 0x0200 != 0
    }
    fn ancount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }
    fn arcount(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[10], resp[11]])
    }

    #[test]
    fn a_query_under_tld_answers_loopback() {
        let resp = respond(&query("x.dig", TYPE_A, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert!(qr(&resp) && aa(&resp));
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        assert_eq!(ancount(&resp), 1);
        assert_eq!(&resp[0..2], &[0x12, 0x34]); // echoed id
                                                // The last 4 bytes of the A answer rdata are the loopback IP.
        assert_eq!(&resp[resp.len() - 4..], &[127, 0, 0, 5]);
        // The answer name is a compression pointer to the question.
        let ans_start = HEADER_LEN + (resp.len() - HEADER_LEN - 16);
        assert_eq!(&resp[ans_start..ans_start + 2], &[0xC0, 0x0C]);
    }

    #[test]
    fn apex_tld_answers() {
        let resp = respond(&query("dig", TYPE_A, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        assert_eq!(ancount(&resp), 1);
    }

    #[test]
    fn aaaa_under_tld_is_nodata() {
        let resp = respond(&query("x.dig", 28, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        assert_eq!(ancount(&resp), 0);
        assert!(aa(&resp));
    }

    #[test]
    fn other_qtype_under_tld_is_nodata() {
        // MX (15) and TXT (16) → NODATA.
        for qt in [15u16, 16, 255] {
            let resp = respond(&query("x.dig", qt, None), IP, "dig", 2, Transport::Udp).unwrap();
            assert_eq!(rcode(&resp), RCODE_NOERROR, "qtype {qt}");
            assert_eq!(ancount(&resp), 0, "qtype {qt}");
        }
    }

    #[test]
    fn non_dig_name_is_refused() {
        let resp = respond(
            &query("example.com", TYPE_A, None),
            IP,
            "dig",
            2,
            Transport::Udp,
        )
        .unwrap();
        assert_eq!(rcode(&resp), RCODE_REFUSED);
        assert_eq!(ancount(&resp), 0);
        assert!(!aa(&resp), "not authoritative for a non-.dig name");
    }

    #[test]
    fn digfoo_is_not_under_dig() {
        // A label that merely starts with the tld is not under it.
        let resp = respond(&query("digfoo", TYPE_A, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(rcode(&resp), RCODE_REFUSED);
    }

    #[test]
    fn deep_subdomain_under_tld_answers() {
        // <root>.<store>.dig (the pinned-capsule host) still resolves.
        let resp = respond(
            &query("aaa.bbb.dig", TYPE_A, None),
            IP,
            "dig",
            2,
            Transport::Udp,
        )
        .unwrap();
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        assert_eq!(ancount(&resp), 1);
    }

    #[test]
    fn zero_x20_case_is_preserved_in_the_question() {
        let resp = respond(&query("X.DiG", TYPE_A, None), IP, "dig", 2, Transport::Udp).unwrap();
        // NOERROR (case-insensitive TLD match) …
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        // … and the echoed question preserves the exact case "X" and "DiG".
        let echoed = &resp[HEADER_LEN..];
        assert_eq!(&echoed[0..2], &[1u8, b'X']); // len 1, 'X'
        assert_eq!(&echoed[2..6], &[3u8, b'D', b'i', b'G']); // len 3, 'DiG'
    }

    #[test]
    fn custom_tld_is_honored() {
        let resp = respond(
            &query("x.web3", TYPE_A, None),
            IP,
            "web3",
            2,
            Transport::Udp,
        )
        .unwrap();
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        assert_eq!(ancount(&resp), 1);
        // The same name is REFUSED under a different served TLD.
        let resp = respond(&query("x.web3", TYPE_A, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(rcode(&resp), RCODE_REFUSED);
    }

    #[test]
    fn edns_opt_is_echoed() {
        let resp = respond(
            &query("x.dig", TYPE_A, Some(4096)),
            IP,
            "dig",
            2,
            Transport::Udp,
        )
        .unwrap();
        assert_eq!(rcode(&resp), RCODE_NOERROR);
        assert_eq!(arcount(&resp), 1, "OPT echoed");
        assert_eq!(ancount(&resp), 1);
        // The trailing OPT record: root name 0x00, type 41.
        let opt = &resp[resp.len() - 11..];
        assert_eq!(opt[0], 0x00);
        assert_eq!(u16::from_be_bytes([opt[1], opt[2]]), TYPE_OPT);
    }

    #[test]
    fn udp_overflow_sets_tc_and_drops_answer() {
        // A tiny advertised EDNS UDP size forces truncation of our (larger) A response.
        let resp = respond(
            &query("x.dig", TYPE_A, Some(20)),
            IP,
            "dig",
            2,
            Transport::Udp,
        )
        .unwrap();
        assert!(tc(&resp), "TC set on UDP overflow");
        assert_eq!(ancount(&resp), 0, "answer dropped under TC");
    }

    #[test]
    fn tcp_never_truncates() {
        // The same tiny EDNS size does NOT truncate over TCP (no UDP size limit).
        let resp = respond(
            &query("x.dig", TYPE_A, Some(20)),
            IP,
            "dig",
            2,
            Transport::Tcp,
        )
        .unwrap();
        assert!(!tc(&resp));
        assert_eq!(ancount(&resp), 1);
    }

    #[test]
    fn short_message_is_dropped() {
        assert_eq!(respond(&[0u8; 4], IP, "dig", 2, Transport::Udp), None);
    }

    #[test]
    fn malformed_question_is_formerr() {
        // A header claiming a question but with a truncated name → FORMERR, no question echoed.
        let mut m = query("x.dig", TYPE_A, None);
        m.truncate(HEADER_LEN + 1); // header + a stray length byte, no terminator
        let resp = respond(&m, IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(rcode(&resp), RCODE_FORMERR);
        assert_eq!(ancount(&resp), 0);
    }

    #[test]
    fn ttl_is_written_into_the_answer() {
        let resp = respond(&query("x.dig", TYPE_A, None), IP, "dig", 5, Transport::Udp).unwrap();
        // TTL is the 4 bytes just before rdlength(2)+rdata(4) at the end.
        let ttl_bytes = &resp[resp.len() - 10..resp.len() - 6];
        assert_eq!(u32::from_be_bytes(ttl_bytes.try_into().unwrap()), 5);
    }

    #[test]
    fn build_query_round_trips_through_respond_and_parse() {
        // A client query built here, answered by respond(), parses back to the served IP.
        let q = build_a_query("mystore.dig");
        let resp = respond(&q, IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(parse_first_a_ipv4(&resp), Some(IP));
    }

    #[test]
    fn parse_first_a_is_none_for_nodata_and_refused() {
        // AAAA under .dig → NODATA (no A answer).
        let resp = respond(&query("x.dig", 28, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(parse_first_a_ipv4(&resp), None);
        // non-.dig → REFUSED (no answer).
        let resp = respond(&query("x.com", TYPE_A, None), IP, "dig", 2, Transport::Udp).unwrap();
        assert_eq!(parse_first_a_ipv4(&resp), None);
    }

    #[test]
    fn parse_first_a_handles_edns_and_short_input() {
        // With an EDNS OPT echoed in the additional section, the A answer is still found.
        let resp = respond(
            &query("x.dig", TYPE_A, Some(4096)),
            IP,
            "dig",
            2,
            Transport::Udp,
        )
        .unwrap();
        assert_eq!(parse_first_a_ipv4(&resp), Some(IP));
        // Too short to hold a header → None (never panics).
        assert_eq!(parse_first_a_ipv4(&[0u8; 4]), None);
    }
}

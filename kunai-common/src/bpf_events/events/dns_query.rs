use crate::bpf_events::Event;
use crate::net::{IpProto, SocketInfo};
use crate::{buffer::Buffer, net::SockAddr};

pub const DNS_MAX_PACKET_SIZE: usize = 2048;

#[repr(C)]
#[derive(Debug, Clone)]
pub enum DnsError {
    None,
    MissingData,
    TruncatedData,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct DnsQueryData {
    pub socket: SocketInfo,
    pub src: SockAddr,
    pub dst: SockAddr,
    pub data: Buffer<DNS_MAX_PACKET_SIZE>,
    pub tcp_header: bool,
    pub error: DnsError,
}

pub type DnsQueryEvent = Event<DnsQueryData>;

impl DnsQueryData {
    pub fn header_is_null(&self) -> bool {
        let h = &self.packet_data()[..12];
        h.iter().filter(|&&b| b == 0).count() == 12
    }

    pub fn packet_data(&self) -> &[u8] {
        // this is a TCP connection
        if self.socket.proto == IpProto::TCP as u16 && self.tcp_header && self.data.len() >= 14 {
            // there are two bytes at front encoding the size of the packet
            return &self.data.as_slice()[2..];
        }
        self.data.as_slice()
    }
}

#[cfg(feature = "user")]
pub use user::*;

#[cfg(feature = "user")]
mod user {
    use super::*;
    use base64ct::{Base64, Encoding};
    use gene_encoding::escape_invalid_utf8_or_byte;
    use simple_dns::{
        Name, Packet, QTYPE, ResourceRecord, SimpleDnsError, TYPE,
        rdata::{RData, TXT},
    };
    use std::{
        borrow::Cow,
        collections::{HashMap, hash_map::Entry},
        net::{Ipv4Addr, Ipv6Addr},
        vec::Vec,
    };

    /// Represents a DNS query response for a specific domain.
    ///
    /// This struct contains the results of a DNS query, including the domain name,
    /// the type of query, and the associated answers from the DNS response.
    pub struct DomainResponse {
        /// The domain name that was queried.
        pub qname: String,
        /// The type of DNS query (e.g., "A", "AAAA", "CNAME", "MX", etc.).
        pub qtype: Cow<'static, str>,
        /// A list of string representations of the DNS resource records that answer the query.
        ///
        /// For different record types, this contains:
        /// - A records: IPv4 addresses
        /// - AAAA records: IPv6 addresses
        /// - CNAME records: Canonical names
        /// - MX records: Mail exchange servers
        /// - NS records: Name servers
        /// - TXT records: Text records
        pub records: Vec<String>,
    }

    const LABEL_SEPARATOR: u8 = b'.';

    /// Converts a DNS name to text. ASCII letters are lowercased, since DNS
    /// names are case-insensitive for them only (RFC 4343). Labels are joined
    /// with `.`, invalid UTF-8 bytes are written as `\xNN` and a `.` inside a
    /// label as `\x2e`, so a name cannot look like another one and decodes
    /// back to its lowercased label bytes.
    fn name_to_string(name: &Name) -> String {
        let labels: Vec<String> = name
            .as_bytes()
            .map(|label| {
                escape_invalid_utf8_or_byte(&label.to_ascii_lowercase(), LABEL_SEPARATOR)
                    .into_owned()
            })
            .collect();
        labels.join(".")
    }

    const TXT_SEPARATOR: u8 = b';';

    /// Converts TXT strings to text, in packet order, joined with `;`.
    /// Invalid UTF-8 bytes are written as `\xNN` and a `;` inside a string
    /// as `\x3b`, so no string is lost or split.
    fn txt_to_string(txt: &TXT) -> String {
        let mut strings = vec![];
        for (key, value) in txt.iter_raw() {
            // iter_raw splits each string on its first '=', we put it back
            let mut raw = key.to_vec();
            if let Some(value) = value {
                raw.push(b'=');
                raw.extend_from_slice(value);
            }
            strings.push(escape_invalid_utf8_or_byte(&raw, TXT_SEPARATOR).into_owned());
        }
        strings.join(";")
    }

    #[inline(always)]
    fn rdata_to_string(rdata: &RData) -> String {
        match rdata {
            RData::A(r) => Ipv4Addr::from(r.address).to_string(),
            RData::AAAA(r) => Ipv6Addr::from(r.address).to_string(),
            RData::CNAME(r) => name_to_string(&r.0),
            RData::MX(r) => name_to_string(&r.exchange),
            RData::NS(r) => name_to_string(&r.0),
            RData::PTR(r) => name_to_string(&r.0),
            RData::SRV(r) => name_to_string(&r.target),
            RData::TXT(r) => txt_to_string(r),
            RData::MD(md) => name_to_string(&md.0),
            RData::MB(mb) => name_to_string(&mb.0),
            RData::MG(mg) => name_to_string(&mg.0),
            RData::MR(mr) => name_to_string(&mr.0),
            RData::MF(mf) => name_to_string(&mf.0),
            RData::HINFO(hinfo) => format!("cpu={} os={}", hinfo.cpu, hinfo.os),
            RData::MINFO(minfo) => format!(
                "rmailbox={} emailbox={}",
                name_to_string(&minfo.rmailbox),
                name_to_string(&minfo.emailbox)
            ),
            RData::SOA(soa) => format!(
                "mname={} rname={} serial={} refresh={} retry={} expire={} minimum={}",
                name_to_string(&soa.mname),
                name_to_string(&soa.rname),
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum
            ),
            RData::WKS(wks) => format!("address={} protocol={}", wks.address, wks.protocol),
            RData::RP(rp) => format!(
                "mbox={} txt={}",
                name_to_string(&rp.mbox),
                name_to_string(&rp.txt)
            ),
            RData::AFSDB(afsdb) => format!(
                "subtype={} hostname={}",
                afsdb.subtype,
                name_to_string(&afsdb.hostname)
            ),
            RData::ISDN(isdn) => format!("address={} sa={}", isdn.address, isdn.sa),
            RData::RouteThrough(route_through) => format!(
                "intermediate_host={} preference={}",
                name_to_string(&route_through.intermediate_host),
                route_through.preference
            ),
            RData::NAPTR(naptr) => format!(
                "order={} preference={} flags={} services={} regexp={} replacement={}",
                naptr.order,
                naptr.preference,
                naptr.flags,
                naptr.services,
                naptr.regexp,
                name_to_string(&naptr.replacement)
            ),
            RData::NSAP(nsap) => format!(
                "{:02x}.{:04x}.{:02x}.{:06x}.{:04x}.{:04x}.{:04x}.{:012x}.{:02x}",
                nsap.afi,
                nsap.idi,
                nsap.dfi,
                nsap.aa,
                nsap.rsvd,
                nsap.rd,
                nsap.area,
                nsap.id,
                nsap.sel
            ),
            RData::NSAP_PTR(nsap_ptr) => name_to_string(&nsap_ptr.0),
            RData::LOC(loc) => format!(
                "version={} size={} horizontal_precision={} vertical_precision={} latitude={} \
                 longitude={} altitude={}",
                loc.version,
                loc.size,
                loc.horizontal_precision,
                loc.vertical_precision,
                loc.latitude,
                loc.longitude,
                loc.altitude
            ),
            RData::OPT(opt) => {
                // we don't format opt_codes to simplify output, let's wait and see if that is an issue for users
                format!(
                    "udp_packet_size={} version={}",
                    opt.udp_packet_size, opt.version
                )
            }
            RData::CAA(caa) => format!(
                "flag={} tag={} value={}",
                caa.flag,
                caa.tag,
                Base64::encode_string(&caa.value)
            ),
            RData::SVCB(svcb) => format!(
                "priority={} target={}",
                svcb.priority,
                name_to_string(&svcb.target)
            ),
            RData::HTTPS(https) => {
                format!(
                    "priority={} target={}",
                    https.0.priority,
                    name_to_string(&https.0.target)
                )
            }
            RData::EUI48(eui48) => {
                let mac = &eui48.address;
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )
            }
            RData::EUI64(eui64) => {
                let eui = &eui64.address;
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    eui[0], eui[1], eui[2], eui[3], eui[4], eui[5], eui[6], eui[7]
                )
            }
            RData::CERT(cert) => format!(
                "type={} key_tag={} algorithm={} certificate={}",
                cert.type_code,
                cert.key_tag,
                cert.algorithm,
                Base64::encode_string(&cert.certificate)
            ),
            RData::ZONEMD(zonemd) => format!(
                "serial={} scheme={} algorithm={} digest={}",
                zonemd.serial,
                zonemd.scheme,
                zonemd.algorithm,
                Base64::encode_string(&zonemd.digest)
            ),
            RData::KX(kx) => format!(
                "preference={} exchanger={}",
                kx.preference,
                name_to_string(&kx.exchanger)
            ),
            RData::IPSECKEY(ipseckey) => {
                let gw = match &ipseckey.gateway {
                    simple_dns::rdata::Gateway::None => "none".into(),
                    simple_dns::rdata::Gateway::IPv4(ipv4_addr) => ipv4_addr.to_string(),
                    simple_dns::rdata::Gateway::IPv6(ipv6_addr) => ipv6_addr.to_string(),
                    simple_dns::rdata::Gateway::Domain(name) => name_to_string(name),
                };
                format!(
                    "precedence={} algorithm={} gateway={} public_key={}",
                    ipseckey.precedence,
                    ipseckey.algorithm,
                    gw,
                    Base64::encode_string(&ipseckey.public_key)
                )
            }
            RData::DNSKEY(dnskey) => format!(
                "flags={} protocol={} algorithm={} public_key={}",
                dnskey.flags,
                dnskey.protocol,
                dnskey.algorithm,
                Base64::encode_string(&dnskey.public_key)
            ),
            RData::RRSIG(rrsig) => format!(
                "type_covered={} algorithm={} labels={} original_ttl={} signature_expiration={} \
                 signature_inception={} key_tag={} signer={} signature={}",
                rrsig.type_covered,
                rrsig.algorithm,
                rrsig.labels,
                rrsig.original_ttl,
                rrsig.signature_expiration,
                rrsig.signature_inception,
                rrsig.key_tag,
                name_to_string(&rrsig.signer_name),
                Base64::encode_string(&rrsig.signature)
            ),
            RData::DS(ds) => format!(
                "key_tag={} algorithm={} digest_type={} digest={}",
                ds.key_tag,
                ds.algorithm,
                ds.digest_type,
                Base64::encode_string(&ds.digest)
            ),
            RData::NSEC(nsec) => {
                // we don't format type_bit_maps to simplify output, let's wait and see if that is an issue for users
                format!("next_domain={}", name_to_string(&nsec.next_name))
            }
            RData::DHCID(dhcid) => format!(
                "identifier={} digest_type={} digest={}",
                dhcid.identifier,
                dhcid.digest_type,
                Base64::encode_string(&dhcid.digest)
            ),
            RData::NULL(_, null) => {
                let data = null.get_data();
                if !data.is_empty() {
                    format!("any={}", Base64::encode_string(null.get_data()))
                } else {
                    "null".into()
                }
            }
            RData::Empty(_) => "empty rdata".to_string(),
        }
    }

    #[inline(always)]
    fn qtype_as_str(qtype: &QTYPE) -> &'static str {
        match qtype {
            QTYPE::TYPE(t) => match t {
                TYPE::A => "A",
                TYPE::AAAA => "AAAA",
                TYPE::NS => "NS",
                TYPE::MD => "MD",
                TYPE::CNAME => "CNAME",
                TYPE::MB => "MB",
                TYPE::MG => "MG",
                TYPE::MR => "MR",
                TYPE::PTR => "PTR",
                TYPE::MF => "MF",
                TYPE::HINFO => "HINFO",
                TYPE::MINFO => "MINFO",
                TYPE::MX => "MX",
                TYPE::TXT => "TXT",
                TYPE::SOA => "SOA",
                TYPE::WKS => "WKS",
                TYPE::SRV => "SRV",
                TYPE::RP => "RP",
                TYPE::AFSDB => "AFSDB",
                TYPE::ISDN => "ISDN",
                TYPE::RouteThrough => "RouteThrough",
                TYPE::NAPTR => "NAPTR",
                TYPE::NSAP => "NSAP",
                TYPE::NSAP_PTR => "NSAP_PTR",
                TYPE::LOC => "LOC",
                TYPE::OPT => "OPT",
                TYPE::CAA => "CAA",
                TYPE::SVCB => "SVCB",
                TYPE::HTTPS => "HTTPS",
                TYPE::EUI48 => "EUI48",
                TYPE::EUI64 => "EUI64",
                TYPE::CERT => "CERT",
                TYPE::ZONEMD => "ZONEMD",
                TYPE::KX => "KX",
                TYPE::IPSECKEY => "IPSECKEY",
                TYPE::DNSKEY => "DNSKEY",
                TYPE::RRSIG => "RRSIG",
                TYPE::DS => "DS",
                TYPE::NSEC => "NSEC",
                TYPE::DHCID => "DHCID",
                TYPE::NULL => "NULL",
                TYPE::Unknown(_) => "?",
                _ => "?",
            },
            QTYPE::AXFR => "AXFR",
            QTYPE::IXFR => "IXFR",
            QTYPE::MAILB => "MAILB",
            QTYPE::MAILA => "MAILA",
            QTYPE::ANY => "ANY",
        }
    }

    impl DnsQueryData {
        /// Parses DNS packet data and returns responses grouped by domain name.
        ///
        /// This function extracts DNS query responses from the packet data and organizes them
        /// by domain name. For each domain query, it collects all associated resource records
        /// and handles CNAME records by including both the CNAME and its target resolution.
        ///
        /// # Returns
        ///
        /// A vector of `DomainResponse` structs, each containing:
        /// - `qname`: The queried domain name
        /// - `qtype`: The query type (e.g., "A", "AAAA", "CNAME")
        /// - `answers`: A list of string representations of the resource records
        ///
        /// # Errors
        ///
        /// Returns `dns_parser::Error` if the DNS packet cannot be parsed or is malformed.
        pub fn domain_responses(&self) -> Result<Vec<DomainResponse>, SimpleDnsError> {
            let packet = Packet::parse(self.packet_data())?;
            let mut out: Vec<DomainResponse> = vec![];

            let mut domain_records: HashMap<String, Vec<ResourceRecord<'_>>> = HashMap::new();
            packet.answers.into_iter().for_each(|r| {
                match domain_records.entry(name_to_string(&r.name)) {
                    Entry::Occupied(mut occupied_entry) => occupied_entry.get_mut().push(r),
                    Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(vec![r]);
                    }
                };
            });

            for q in packet.questions.iter() {
                let mut cname_resp = None;

                let qname = name_to_string(&q.qname);

                if let Some(records) = domain_records.remove(&qname) {
                    for r in records.iter() {
                        // we have a CNAME in response so we must also
                        // have the matching record for that one
                        if let RData::CNAME(cname) = &r.rdata {
                            let cname_str = name_to_string(&cname.0);
                            // check if we have response for the CNAME record
                            if let Some(records) = domain_records.remove(&cname_str) {
                                cname_resp = Some(DomainResponse {
                                    qname: cname_str,
                                    qtype: Cow::Borrowed(qtype_as_str(&q.qtype)),
                                    records: records
                                        .into_iter()
                                        .map(|r| rdata_to_string(&r.rdata))
                                        .collect(),
                                });
                            }
                        }
                    }

                    out.push(DomainResponse {
                        qname,
                        qtype: Cow::Borrowed(qtype_as_str(&q.qtype)),
                        records: records
                            .into_iter()
                            .map(|r| rdata_to_string(&r.rdata))
                            .collect(),
                    });

                    // we push cname_resp at the end so that we first see
                    // the CNAME record in the logs
                    if let Some(r) = cname_resp {
                        out.push(r)
                    }
                }
            }
            Ok(out)
        }
    }
}

#[cfg(all(test, feature = "user"))]
mod tests {
    use super::*;
    use gene_encoding::unescape_invalid_utf8;
    use simple_dns::{
        CLASS, CharacterString, Label, Name, Packet, QCLASS, QTYPE, Question, ResourceRecord, TYPE,
        rdata::{A, CNAME, RData, TXT},
    };

    const TTL: u32 = 60;
    const IP_1_2_3_4: u32 = 0x01020304;

    fn name<'a>(labels: &[&'a [u8]]) -> Name<'a> {
        let labels: Vec<Label<'a>> = labels.iter().map(|l| Label::new_unchecked(*l)).collect();
        Name::new_with_labels(&labels)
    }

    fn a_record(owner: Name<'_>) -> ResourceRecord<'_> {
        let rdata = RData::A(A {
            address: IP_1_2_3_4,
        });
        ResourceRecord::new(owner, CLASS::IN, TTL, rdata)
    }

    fn query_data(question: Name<'_>, answers: Vec<ResourceRecord<'_>>) -> DnsQueryData {
        let mut packet = Packet::new_reply(1);
        packet.questions.push(Question::new(
            question,
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers = answers;

        DnsQueryData {
            socket: SocketInfo::default(),
            src: SockAddr::default(),
            dst: SockAddr::default(),
            data: Buffer::from_bytes(&packet.build_bytes_vec().unwrap()),
            tcp_header: false,
            error: DnsError::None,
        }
    }

    /// Returns the records printed for a single TXT answer made of `strings`.
    fn txt_records(strings: &[&[u8]]) -> Vec<String> {
        let mut txt = TXT::new();
        for string in strings {
            txt.add_char_string(CharacterString::new(string).unwrap());
        }
        let owner = name(&[b"www", b"example"]);
        let record = ResourceRecord::new(owner.clone(), CLASS::IN, TTL, RData::TXT(txt));

        let responses = query_data(owner, vec![record]).domain_responses().unwrap();

        assert_eq!(responses.len(), 1);
        responses.into_iter().next().unwrap().records
    }

    #[test]
    fn label_dot_is_escaped() {
        let data = query_data(
            name(&[b"good.example"]),
            vec![a_record(name(&[b"good.example"]))],
        );

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].qname, r"good\x2eexample");
        assert_eq!(responses[0].records, ["1.2.3.4"]);
    }

    #[test]
    fn label_dot_does_not_match_label_separator() {
        // the answer is for good.example, not for the single label "good.example"
        let data = query_data(
            name(&[b"good.example"]),
            vec![a_record(name(&[b"good", b"example"]))],
        );

        assert!(data.domain_responses().unwrap().is_empty());
    }

    #[test]
    fn invalid_utf8_label_is_escaped() {
        let data = query_data(
            name(&[b"bad\xff", b"example"]),
            vec![a_record(name(&[b"bad\xff", b"example"]))],
        );

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].qname, r"bad\xff.example");
    }

    #[test]
    fn backslash_before_label_dot_round_trips() {
        let data = query_data(name(&[b"a\\.b"]), vec![a_record(name(&[b"a\\.b"]))]);

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].qname, r"a\\\x2eb");
        assert_eq!(&*unescape_invalid_utf8(&responses[0].qname), b"a\\.b");
    }

    #[test]
    fn cname_target_label_dot_is_escaped() {
        let cname = ResourceRecord::new(
            name(&[b"www", b"example"]),
            CLASS::IN,
            TTL,
            RData::CNAME(CNAME(name(&[b"cdn.evil", b"com"]))),
        );
        let data = query_data(
            name(&[b"www", b"example"]),
            vec![cname, a_record(name(&[b"cdn.evil", b"com"]))],
        );

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].qname, "www.example");
        assert_eq!(responses[0].records, [r"cdn\x2eevil.com"]);
        assert_eq!(responses[1].qname, r"cdn\x2eevil.com");
        assert_eq!(responses[1].records, ["1.2.3.4"]);
    }

    #[test]
    fn name_is_lowercased() {
        // the answer's case differs from the question's (0x20 encoding)
        let data = query_data(
            name(&[b"EvIl", b"CoM"]),
            vec![a_record(name(&[b"evil", b"com"]))],
        );

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].qname, "evil.com");
        assert_eq!(responses[0].records, ["1.2.3.4"]);
    }

    #[test]
    fn cname_target_is_lowercased() {
        let cname = ResourceRecord::new(
            name(&[b"www", b"example"]),
            CLASS::IN,
            TTL,
            RData::CNAME(CNAME(name(&[b"CDN", b"Evil", b"com"]))),
        );
        let data = query_data(
            name(&[b"www", b"example"]),
            vec![cname, a_record(name(&[b"cdn", b"evil", b"com"]))],
        );

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].records, ["cdn.evil.com"]);
        assert_eq!(responses[1].qname, "cdn.evil.com");
        assert_eq!(responses[1].records, ["1.2.3.4"]);
    }

    #[test]
    fn only_ascii_letters_are_lowercased() {
        // DNS names are case-insensitive for ASCII letters only (RFC 4343)
        let data = query_data(
            name(&["ÉVIL".as_bytes(), b"com"]),
            vec![a_record(name(&["Évil".as_bytes(), b"com"]))],
        );

        let responses = data.domain_responses().unwrap();

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].qname, "Évil.com");
    }

    #[test]
    fn txt_keeps_invalid_utf8_key() {
        assert_eq!(txt_records(&[b"k\xff=v"]), [r"k\xff=v"]);
    }

    #[test]
    fn txt_keeps_invalid_utf8_value() {
        assert_eq!(txt_records(&[b"k=v\xff"]), [r"k=v\xff"]);
    }

    #[test]
    fn txt_keeps_duplicate_keys() {
        assert_eq!(txt_records(&[b"k=1", b"k=2"]), ["k=1;k=2"]);
    }

    #[test]
    fn txt_keeps_string_order() {
        let strings: [&[u8]; 5] = [b"e=5", b"d=4", b"c", b"b=2", b"a="];
        assert_eq!(txt_records(&strings), ["e=5;d=4;c;b=2;a="]);
    }

    #[test]
    fn txt_semicolon_in_string_is_escaped() {
        // one string holding a ';' must not read like two strings
        assert_eq!(txt_records(&[b"a=1;b=2"]), [r"a=1\x3bb=2"]);
    }

    #[test]
    fn txt_keeps_empty_string() {
        assert_eq!(txt_records(&[b"", b"a"]), [";a"]);
    }
}

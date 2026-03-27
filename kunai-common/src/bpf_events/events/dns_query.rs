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
    use simple_dns::{rdata::RData, Packet, ResourceRecord, SimpleDnsError, QTYPE, TYPE};
    use std::{
        borrow::Cow,
        collections::{hash_map::Entry, HashMap},
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

    #[inline(always)]
    fn rdata_to_string(rdata: &RData) -> String {
        match rdata {
            RData::A(r) => Ipv4Addr::from(r.address).to_string(),
            RData::AAAA(r) => Ipv6Addr::from(r.address).to_string(),
            RData::CNAME(r) => r.0.to_string(),
            RData::MX(r) => r.exchange.to_string(),
            RData::NS(r) => r.0.to_string(),
            RData::PTR(r) => r.0.to_string(),
            RData::SRV(r) => r.target.to_string(),
            RData::TXT(r) => {
                let mut out = vec![];
                for (key, value) in r.attributes() {
                    let mut txt = key;
                    if let Some(v) = value {
                        txt.push('=');
                        txt.push_str(&v);
                    }
                    out.push(txt);
                }
                out.join(";")
            }
            RData::MD(md) => md.0.to_string(),
            RData::MB(mb) => mb.0.to_string(),
            RData::MG(mg) => mg.0.to_string(),
            RData::MR(mr) => mr.0.to_string(),
            RData::MF(mf) => mf.0.to_string(),
            RData::HINFO(hinfo) => format!("cpu={} os={}", hinfo.cpu, hinfo.os),
            RData::MINFO(minfo) => {
                format!("rmailbox={} emailbox={}", minfo.rmailbox, minfo.emailbox)
            }
            RData::SOA(soa) => format!(
                "mname={} rname={} serial={} refresh={} retry={} expire={} minimum={}",
                soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
            ),
            RData::WKS(wks) => format!("address={} protocol={}", wks.address, wks.protocol),
            RData::RP(rp) => format!("mbox={} txt={}", rp.mbox, rp.txt),
            RData::AFSDB(afsdb) => format!("subtype={} hostname={}", afsdb.subtype, afsdb.hostname),
            RData::ISDN(isdn) => format!("address={} sa={}", isdn.address, isdn.sa),
            RData::RouteThrough(route_through) => format!(
                "intermediate_host={} preference={}",
                route_through.intermediate_host, route_through.preference
            ),
            RData::NAPTR(naptr) => format!(
                "order={} preference={} flags={} services={} regexp={} replacement={}",
                naptr.order,
                naptr.preference,
                naptr.flags,
                naptr.services,
                naptr.regexp,
                naptr.replacement
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
            RData::NSAP_PTR(nsap_ptr) => nsap_ptr.0.to_string(),
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
            RData::SVCB(svcb) => format!("priority={} target={}", svcb.priority, svcb.target),
            RData::HTTPS(https) => {
                format!("priority={} target={}", https.0.priority, https.0.target)
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
            RData::KX(kx) => format!("preference={} exchanger={}", kx.preference, kx.exchanger),
            RData::IPSECKEY(ipseckey) => {
                let gw = match &ipseckey.gateway {
                    simple_dns::rdata::Gateway::None => "none".into(),
                    simple_dns::rdata::Gateway::IPv4(ipv4_addr) => ipv4_addr.to_string(),
                    simple_dns::rdata::Gateway::IPv6(ipv6_addr) => ipv6_addr.to_string(),
                    simple_dns::rdata::Gateway::Domain(name) => name.to_string(),
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
                rrsig.signer_name,
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
                format!("next_domain={}", nsec.next_name)
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
                match domain_records.entry(r.name.to_string()) {
                    Entry::Occupied(mut occupied_entry) => occupied_entry.get_mut().push(r),
                    Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(vec![r]);
                    }
                };
            });

            for q in packet.questions.iter() {
                let mut cname_resp = None;

                if let Some(records) = domain_records.remove(&q.qname.to_string()) {
                    for r in records.iter() {
                        // we have a CNAME in response so we must also
                        // have the matching record for that one
                        if let RData::CNAME(cname) = &r.rdata {
                            let cname_str = cname.0.to_string();
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
                        qname: q.qname.to_string(),
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

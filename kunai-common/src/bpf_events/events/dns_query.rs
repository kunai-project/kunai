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
    use dns_parser::{self, rdata::RData, Packet, QueryType, ResourceRecord};
    use std::{
        borrow::Cow,
        collections::{hash_map::Entry, HashMap},
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
            RData::A(r) => r.0.to_string(),
            RData::AAAA(r) => r.0.to_string(),
            RData::CNAME(r) => r.0.to_string(),
            RData::MX(r) => r.exchange.to_string(),
            RData::NS(r) => r.0.to_string(),
            RData::PTR(r) => r.0.to_string(),
            RData::SOA(r) => format!("PRIMARY_NS={} MAILBOX={}", r.primary_ns, r.mailbox),
            RData::SRV(r) => r.target.to_string(),
            RData::TXT(r) => {
                let mut out = vec![];
                for txt in r.iter() {
                    match str::from_utf8(txt) {
                        Ok(s) => out.push(String::from(s)),
                        Err(_) => out.push(format!("base64:{}", Base64::encode_string(txt))),
                    }
                }
                out.join(";")
            }
            RData::Unknown(items) => format!("base64:{}", Base64::encode_string(items)),
        }
    }

    #[inline(always)]
    fn qtype_as_str(qtype: &QueryType) -> &'static str {
        match qtype {
            QueryType::A => "A",
            QueryType::NS => "NS",
            QueryType::MF => "MF",
            QueryType::CNAME => "CNAME",
            QueryType::SOA => "SOA",
            QueryType::MB => "MB",
            QueryType::MG => "MG",
            QueryType::MR => "MR",
            QueryType::NULL => "NULL",
            QueryType::WKS => "WKS",
            QueryType::PTR => "PTR",
            QueryType::HINFO => "HINFO",
            QueryType::MINFO => "MINFO",
            QueryType::MX => "MX",
            QueryType::TXT => "TXT",
            QueryType::AAAA => "AAAA",
            QueryType::SRV => "SRV",
            QueryType::AXFR => "AXFR",
            QueryType::MAILB => "MAILB",
            QueryType::MAILA => "MAILA",
            QueryType::All => "ALL",
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
        pub fn domain_responses(&self) -> Result<Vec<DomainResponse>, dns_parser::Error> {
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
                        if let RData::CNAME(cname) = r.data {
                            let cname_str = cname.0.to_string();
                            // check if we have response for the CNAME record
                            if let Some(records) = domain_records.remove(&cname_str) {
                                cname_resp = Some(DomainResponse {
                                    qname: cname_str,
                                    qtype: Cow::Borrowed(qtype_as_str(&q.qtype)),
                                    records: records
                                        .into_iter()
                                        .map(|r| rdata_to_string(&r.data))
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
                            .map(|r| rdata_to_string(&r.data))
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

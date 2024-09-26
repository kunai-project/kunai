use crate::bpf_events::Event;
use crate::macros::not_bpf_target_code;
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
        return self.data.as_slice();
    }
}

not_bpf_target_code! {

    use dns_parser::{self, rdata::RData, Packet};
    use std::vec::Vec;

    pub struct DnsResponse {
        pub question: String,
        pub answers: Vec<String>,
    }

    impl DnsQueryData {
        pub fn answers(&self) -> Result<Vec<DnsResponse>, dns_parser::Error> {
            let packet = Packet::parse(self.packet_data())?;
            let mut out: Vec<DnsResponse> = vec![];

            // we append the domain queried
            let mut domains = packet
            .questions
            .iter()
            .map(|q| q.qname.to_string())
            .collect::<Vec<String>>();

            // we grab all the CNAMES resolved and we push them to the list of domains
            packet
            .answers
            .iter()
            .filter(|r| matches!(r.data, RData::CNAME(_)))
            .for_each(|r| {
                let d = match r.data {
                    RData::CNAME(cname) => cname.0.to_string(),
                    _ => {
                        panic!("unknow record type")
                    }
                };

                domains.push(d);
            });

            // we go through the list of domains and collect A and AAAA records
            for d in domains {
                let answers = packet
                .answers
                .iter()
                .filter(|r| {
                    matches!(r.data, RData::A(_) | RData::AAAA(_) | RData::CNAME(_))
                    && r.name.to_string() == d
                })
                .map(|r| match r.data {
                    RData::A(ip) => ip.0.to_string(),
                    RData::AAAA(ip) => ip.0.to_string(),
                    RData::CNAME(r) => r.0.to_string(),
                    // we should never panic as we filtered already
                    // by A and AAAA type of record
                    _ => panic!("unknown record type"),
                })
                .collect::<Vec<String>>();

                out.push(DnsResponse {
                    question: d,
                    answers,
                });
            }
            Ok(out)
        }
    }

}

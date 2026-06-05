use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead},
    num::ParseIntError,
};

use thiserror::Error;

const KALLSYMS_PATH: &str = "/proc/kallsyms";
const KPTR_RESTRICT: &str = "/proc/sys/kernel/kptr_restrict";

/// Error type for [`KernelSymbols`] operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    ParseEntry(#[from] ParseEntryError),
}

#[derive(Debug)]
enum SymbolKind {
    Data,
    Text,
    Unused,
}

#[derive(Debug)]
struct SymbolEntry {
    address: u64,
    kind: SymbolKind,
    name: String,
}

/// Error returned when a `/proc/kallsyms` line cannot be parsed.
#[derive(Debug, Error)]
pub enum ParseEntryError {
    #[error("{0}")]
    Address(#[from] ParseIntError),
    #[error("empty symbol name")]
    EmptySymName,
}

impl SymbolEntry {
    fn from_line(line: String) -> Result<Self, ParseEntryError> {
        let mut parts = line.splitn(3, ' ');
        let address = u64::from_str_radix(parts.next().unwrap_or(""), 16)?;
        let kind = match parts.next().unwrap_or("") {
            "t" | "T" => SymbolKind::Text,
            "d" | "D" => SymbolKind::Data,
            _ => SymbolKind::Unused,
        };

        let Some(name) = parts.next().map(String::from) else {
            return Err(ParseEntryError::EmptySymName);
        };

        Ok(Self {
            address,
            kind,
            name,
        })
    }
}

/// Parsed view of kernel symbols from `/proc/kallsyms`.
///
/// Symbols are split into text (`T`/`t`) and data (`D`/`d`) categories.
/// When multiple symbols share a name, only the first address is returned
/// by the lookup methods.
#[derive(Debug, Default)]
pub struct KernelSymbols {
    text: HashMap<String, Vec<u64>>,
    data: HashMap<String, Vec<u64>>,
}

impl KernelSymbols {
    /// Loads kernel symbols from `/proc/kallsyms`.
    ///
    /// Temporarily sets `kptr_restrict` to `1` so that privileged callers
    /// can read non-zero addresses, then restores the original value.
    pub fn from_sys() -> Result<Self, Error> {
        let opt_kptr_restrict_bak = if fs::exists(KPTR_RESTRICT).unwrap_or_default() {
            let v = fs::read_to_string(KPTR_RESTRICT)
                .map_err(|e| io::Error::other(format!("cannot read {KPTR_RESTRICT}: {e}")))?;

            // we allow privileged user to see kernel addresses
            fs::write(KPTR_RESTRICT, "1")
                .map_err(|e| io::Error::other(format!("cannot set {KPTR_RESTRICT}: {e}")))?;

            Some(v)
        } else {
            None
        };

        let f = fs::File::open(KALLSYMS_PATH)
            .map_err(|e| io::Error::other(format!("cannot open {KALLSYMS_PATH}: {e}")))?;
        let result = KernelSymbols::from_reader(f);

        if let Some(kptr_restrict_bak) = opt_kptr_restrict_bak {
            // restore regardless of whether reading succeeded
            fs::write(KPTR_RESTRICT, &kptr_restrict_bak)
                .map_err(|e| io::Error::other(format!("cannot restore {KPTR_RESTRICT}: {e}")))?;
        }

        result
    }

    /// Parses kernel symbols from a reader in `/proc/kallsyms` format.
    #[inline]
    pub fn from_reader<R: io::Read>(r: R) -> Result<Self, Error> {
        let mut ks = KernelSymbols::new();
        let br = io::BufReader::new(r);
        for line in br.lines() {
            ks.add_symbol(SymbolEntry::from_line(line?)?);
        }
        Ok(ks)
    }

    fn new() -> Self {
        Default::default()
    }

    fn add_symbol(&mut self, sym: SymbolEntry) {
        match &sym.kind {
            SymbolKind::Text => {
                self.text
                    .entry(sym.name)
                    .and_modify(|a| a.push(sym.address))
                    .or_insert_with(|| vec![sym.address]);
            }
            SymbolKind::Data => {
                self.data
                    .entry(sym.name)
                    .and_modify(|a| a.push(sym.address))
                    .or_insert_with(|| vec![sym.address]);
            }
            SymbolKind::Unused => {}
        };
    }

    /// Returns `true` if a text symbol with the given name exists.
    #[inline(always)]
    pub fn contains_text_symbol(&self, name: &str) -> bool {
        self.text.contains_key(name)
    }

    /// Returns the address of the first text symbol matching `name`.
    pub fn get_text_symbol_addr(&self, name: &str) -> Option<u64> {
        self.text.get(name).and_then(|addrs| addrs.first().cloned())
    }

    /// Returns the address of the first data symbol matching `name`.
    pub fn get_data_symbol_addr(&self, name: &str) -> Option<u64> {
        self.data.get(name).and_then(|addrs| addrs.first().cloned())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn ks_from_str(s: &str) -> KernelSymbols {
        KernelSymbols::from_reader(s.as_bytes()).expect("failed to parse")
    }

    #[test]
    fn text_symbol_found() {
        let ks = ks_from_str("fffffff812345678 T my_func\n");
        assert!(ks.contains_text_symbol("my_func"));
        assert_eq!(ks.get_text_symbol_addr("my_func"), Some(0xfffffff812345678));
    }

    #[test]
    fn local_text_symbol_found() {
        let ks = ks_from_str("fffffff812345678 t static_func\n");
        assert!(ks.contains_text_symbol("static_func"));
        assert_eq!(
            ks.get_text_symbol_addr("static_func"),
            Some(0xfffffff812345678)
        );
    }

    #[test]
    fn data_symbol_found() {
        let ks = ks_from_str("ffffffff81234000 D memstart_addr\n");
        assert_eq!(
            ks.get_data_symbol_addr("memstart_addr"),
            Some(0xffffffff81234000)
        );
    }

    #[test]
    fn local_data_symbol_found() {
        let ks = ks_from_str("ffffffff81234000 d some_local_var\n");
        assert_eq!(
            ks.get_data_symbol_addr("some_local_var"),
            Some(0xffffffff81234000)
        );
    }

    #[test]
    fn symbol_not_found() {
        let ks = ks_from_str("fffffff812345678 T my_func\n");
        assert!(!ks.contains_text_symbol("other_func"));
        assert_eq!(ks.get_text_symbol_addr("other_func"), None);
        assert_eq!(ks.get_data_symbol_addr("my_func"), None);
    }

    #[test]
    fn multiple_addresses_same_name() {
        let input = "ffffffff81000000 T dup_sym\nffffffff82000000 T dup_sym\n";
        let ks = ks_from_str(input);
        // get_text_symbol_addr returns the first one
        assert_eq!(ks.get_text_symbol_addr("dup_sym"), Some(0xffffffff81000000));
    }

    #[test]
    fn mixed_symbol_types() {
        let input = concat!(
            "ffffffff81000000 T text_sym\n",
            "ffffffff82000000 D data_sym\n",
        );
        let ks = ks_from_str(input);
        assert!(ks.contains_text_symbol("text_sym"));
        assert!(!ks.contains_text_symbol("data_sym"));
        assert_eq!(
            ks.get_data_symbol_addr("data_sym"),
            Some(0xffffffff82000000)
        );
        assert_eq!(ks.get_data_symbol_addr("text_sym"), None);
    }

    #[test]
    fn empty_input() {
        let ks = ks_from_str("");
        assert!(!ks.contains_text_symbol("anything"));
        assert_eq!(ks.get_text_symbol_addr("anything"), None);
    }

    #[test]
    fn parse_invalid_address() {
        let result = KernelSymbols::from_reader("zzzzzz T bad_addr\n".as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_symbol_name() {
        let result = KernelSymbols::from_reader("ffffffff81000000 T\n".as_bytes());
        assert!(result.is_err());
    }
}

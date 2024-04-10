use object::{self, Object, ObjectSection, ObjectSymbol};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("object: {0}")]
    Object(#[from] object::Error),
}

#[derive(Debug, Default, Clone)]
pub struct SymbolInfo {
    pub section_name: String,
}

#[derive(Debug, Default)]
pub struct ElfInfo {
    symbols: HashMap<String, SymbolInfo>,
}

impl ElfInfo {
    pub fn from_raw_elf(data: &[u8]) -> Result<Self, Error> {
        let obj = object::read::File::parse(data)?;
        let mut s: Self = Default::default();

        for sym in obj.symbols() {
            if let Some(section) = sym
                .section_index()
                .and_then(|i| obj.section_by_index(i).ok())
            {
                if let (Ok(sym_name), Ok(sec_name)) = (sym.name(), section.name()) {
                    s.symbols.insert(
                        sym_name.to_string(),
                        SymbolInfo {
                            section_name: sec_name.to_string(),
                        },
                    );
                }
            }
        }
        Ok(s)
    }

    pub fn get_by_symbol_name<S: AsRef<str>>(&self, sym_name: S) -> Option<&SymbolInfo> {
        self.symbols.get(sym_name.as_ref())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        let data = include_bytes!("../../../target/bpfel-unknown-none/debug/kunai-ebpf");
        println!("{:#?}", ElfInfo::from_raw_elf(data.as_slice()).unwrap())
    }
}

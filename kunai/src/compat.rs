use aya::{
    programs::{self, ProgramError},
    Bpf,
};
use aya_obj::generated::bpf_prog_type;
use kunai_common::version::KernelVersion;

use std::collections::HashMap;

use crate::util::elf::{self, ElfInfo, SymbolInfo};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("missing tracepoint category for program: {0}")]
    NoTpCategory(String),
    #[error("missing kernel attach function for program: {0}")]
    NoAttachFn(String),
    #[error("{0}")]
    Program(#[from] ProgramError),
}

#[derive(Default)]
pub struct Compatibility {
    min: Option<KernelVersion>,
    max: Option<KernelVersion>,
}

impl Compatibility {
    pub fn min(&self) -> &KernelVersion {
        self.min.as_ref().unwrap_or(&KernelVersion::MIN_VERSION)
    }

    pub fn max(&self) -> &KernelVersion {
        self.max.as_ref().unwrap_or(&KernelVersion::MAX_VERSION)
    }

    fn is_compatible(&self, with: &KernelVersion) -> bool {
        self.min.as_ref().unwrap_or(&KernelVersion::MIN_VERSION) <= with
            && with <= self.max.as_ref().unwrap_or(&KernelVersion::MAX_VERSION)
    }
}

pub struct Programs<'a> {
    m: HashMap<String, Program<'a>>,
}

impl<'a> Programs<'a> {
    pub fn from_bpf(bpf: &'a mut Bpf) -> Self {
        let m = bpf
            .programs_mut()
            .map(|(name, p)| {
                // only supports . encoding for the moment
                //let unmangled_name = name.replace("_", ".");
                let unmangled_name = name.to_string();
                let prog = Program::from_program(unmangled_name.clone(), p);
                (unmangled_name, prog)
            })
            .collect();

        Self { m }
    }

    pub fn with_elf_info(mut self, data: &[u8]) -> Result<Self, elf::Error> {
        let elf_info = ElfInfo::from_raw_elf(data)?;
        // prog_name is an Elf symbol name
        for (prog_name, prog) in self.m.iter_mut() {
            prog.info = elf_info.get_by_symbol_name(prog_name).cloned()
        }
        Ok(self)
    }

    pub fn programs(&self) -> Vec<&Program> {
        self.m.values().collect()
    }

    pub fn expect_mut<S: AsRef<str>>(&mut self, name: S) -> &mut Program<'a> {
        self.m
            .get_mut(name.as_ref())
            .expect(&format!("missing probe {}", name.as_ref()))
    }

    pub fn into_vec_sorted_by_prio(self) -> Vec<(String, Program<'a>)> {
        let mut sorted: Vec<(String, Program)> = self.m.into_iter().collect();
        sorted.sort_unstable_by_key(|(_, p)| p.prio_by_prog());
        sorted
    }
}

pub struct Program<'a> {
    pub prio: u8,
    pub name: String,
    pub info: Option<SymbolInfo>,
    pub compat: Compatibility,
    pub program: &'a mut programs::Program,
    pub enable: bool,
}

impl<'a> Program<'a> {
    pub fn from_program(name: String, p: &'a mut programs::Program) -> Self {
        Program {
            prio: 50,
            name,
            info: None,
            program: p,
            compat: Compatibility::default(),
            enable: true,
        }
    }

    /* naturally decrease priority of exit kind of probes to remove map operations errors at BPF load time */
    pub fn prio_by_prog(&self) -> u8 {
        let program = self.prog();

        match program {
            programs::Program::TracePoint(_) => {
                let kernel_attach = self
                    .attach_func()
                    .ok_or(Error::NoAttachFn(self.name.clone()))
                    .unwrap();
                if kernel_attach.starts_with("sys_exit") {
                    return self.prio + 1;
                }
                return self.prio;
            }
            programs::Program::KProbe(program) => match program.kind() {
                programs::ProbeKind::URetProbe => self.prio + 1,
                programs::ProbeKind::KRetProbe => self.prio + 1,
                _ => self.prio,
            },

            programs::Program::FExit(_) => self.prio + 1,

            _ => self.prio,
        }
    }

    #[inline]
    fn attach_func(&self) -> Option<String> {
        self.info
            .as_ref()
            .and_then(|i| i.section_name.split('/').last().map(|s| s.to_string()))
    }

    #[inline]
    fn tracepoint_category(&self) -> Option<String> {
        self.info.as_ref().and_then(|i| {
            let v: Vec<&str> = i.section_name.split('/').collect();
            v.get(v.len() - 2).map(|s| s.to_string())
        })
    }

    pub fn min_kernel(&mut self, min: KernelVersion) -> &mut Self {
        self.compat.min = Some(min);
        self
    }

    pub fn max_kernel(&mut self, max: KernelVersion) -> &mut Self {
        self.compat.max = Some(max);
        self
    }

    pub fn prog_type(&self) -> bpf_prog_type {
        self.program.prog_type()
    }

    pub fn prog(&self) -> &programs::Program {
        self.program
    }

    pub fn prog_mut(&mut self) -> &mut programs::Program {
        self.program
    }

    pub fn is_compatible(&self, kernel: &KernelVersion) -> bool {
        self.compat.is_compatible(kernel)
    }

    pub fn rename<T: AsRef<str>>(&mut self, new: T) {
        self.name = new.as_ref().to_string();
    }

    pub fn rename_if<T: AsRef<str>>(&mut self, cond: bool, new: T) {
        if cond {
            self.rename(new)
        }
    }

    pub fn enable(&mut self) {
        self.enable = true
    }

    pub fn disable(&mut self) {
        self.enable = false
    }

    pub fn attach(&mut self) -> Result<(), Error> {
        let program_name = self.name.clone();
        let kernel_attach_fn = self.attach_func();
        let tracepoint_category = self.tracepoint_category();
        let program = self.prog_mut();

        match program {
            programs::Program::TracePoint(program) => {
                program.load()?;
                let cat = tracepoint_category.ok_or(Error::NoTpCategory(program_name.clone()))?;
                let attach = kernel_attach_fn.ok_or(Error::NoAttachFn(program_name))?;
                program.attach(&cat, &attach)?;
            }
            programs::Program::KProbe(program) => {
                program.load()?;
                let attach = kernel_attach_fn.ok_or(Error::NoAttachFn(program_name))?;
                program.attach(attach, 0)?;
            }
            _ => {
                unimplemented!()
            }
        }
        Ok(())
    }
}

use aya::{
    programs::{
        self, kprobe::KProbeLinkId, lsm::LsmLinkId, trace_point::TracePointLinkId, ProgramError,
        ProgramType,
    },
    Btf, Ebpf,
};
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
    #[error("wrong link id kind")]
    WrongLinkId,
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
    pub fn with_bpf(bpf: &'a mut Ebpf) -> Self {
        let m = bpf
            .programs_mut()
            .map(|(name, p)| {
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
            .unwrap_or_else(|| panic!("missing probe {}", name.as_ref()))
    }

    pub fn into_vec_sorted_by_prio(self) -> Vec<(String, Program<'a>)> {
        let mut sorted: Vec<(String, Program)> = self.m.into_iter().collect();
        sorted.sort_unstable_by_key(|(_, p)| p.prio_by_prog());
        sorted
    }

    pub fn sorted_by_prio(&mut self) -> Vec<(&String, &mut Program<'a>)> {
        let mut sorted = self.m.iter_mut().collect::<Vec<_>>();
        sorted.sort_unstable_by_key(|(_, p)| p.prio_by_prog());
        sorted
    }
}

#[derive(Debug)]
pub enum LinkId {
    KProbe(KProbeLinkId),
    Tracepoint(TracePointLinkId),
    Lsm(LsmLinkId),
}

impl TryFrom<LinkId> for KProbeLinkId {
    type Error = Error;
    fn try_from(value: LinkId) -> Result<Self, Self::Error> {
        match value {
            LinkId::KProbe(l) => Ok(l),
            _ => Err(Error::WrongLinkId),
        }
    }
}

impl TryFrom<LinkId> for TracePointLinkId {
    type Error = Error;
    fn try_from(value: LinkId) -> Result<Self, Self::Error> {
        match value {
            LinkId::Tracepoint(l) => Ok(l),
            _ => Err(Error::WrongLinkId),
        }
    }
}

impl TryFrom<LinkId> for LsmLinkId {
    type Error = Error;
    fn try_from(value: LinkId) -> Result<Self, Self::Error> {
        match value {
            LinkId::Lsm(l) => Ok(l),
            _ => Err(Error::WrongLinkId),
        }
    }
}

pub struct Program<'a> {
    pub prio: u8,
    pub name: String,
    pub info: Option<SymbolInfo>,
    pub compat: Compatibility,
    pub program: &'a mut programs::Program,
    pub enable: bool,
    pub link_id: Option<LinkId>,
    pub loaded: bool,
    pub attached: bool,
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
            link_id: None,
            loaded: false,
            attached: false,
        }
    }

    /* naturally decrease priority of exit kind of probes to remove map operations errors at BPF load time */
    pub fn prio_by_prog(&self) -> u8 {
        let program = self.prog();

        match program {
            programs::Program::TracePoint(_) => {
                let kernel_attach = self
                    .attach_point()
                    .ok_or(Error::NoAttachFn(self.name.clone()))
                    .unwrap();
                if kernel_attach.starts_with("sys_exit") {
                    return self.prio + 1;
                }
                self.prio
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

    /// Returns the name of the attach point in kernel land
    #[inline]
    fn attach_point(&self) -> Option<String> {
        self.info
            .as_ref()
            .and_then(|i| i.section_name.split('/').last().map(|s| s.to_string()))
    }

    /// Returns true if the attach point of program is `name`
    #[inline]
    pub fn has_attach_point<S: AsRef<str>>(&self, name: S) -> bool {
        self.attach_point()
            .map(|a| a.as_str() == name.as_ref())
            .unwrap_or_default()
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

    pub fn prio(&mut self, prio: u8) -> &mut Self {
        self.prio = prio;
        self
    }

    pub fn prog_type(&self) -> ProgramType {
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

    pub fn enable(&mut self) -> &mut Self {
        self.enable = true;
        self
    }

    pub fn disable(&mut self) -> &mut Self {
        self.enable = false;
        self
    }

    pub fn disable_if(&mut self, condition: bool) -> &mut Self {
        if condition {
            self.enable = false
        }
        self
    }

    pub fn load(&mut self, btf: &Btf) -> Result<(), Error> {
        let hook = self.attach_point();
        let prog_name = self.name.clone();
        let program = self.prog_mut();

        match program {
            programs::Program::TracePoint(p) => {
                p.load()?;
            }
            programs::Program::KProbe(p) => {
                p.load()?;
            }
            programs::Program::Lsm(p) => {
                let attach = hook.ok_or(Error::NoAttachFn(prog_name))?;
                p.load(&attach, btf)?;
            }
            _ => {
                unimplemented!()
            }
        }
        self.loaded = true;
        Ok(())
    }

    pub fn unload(&mut self) -> Result<(), Error> {
        let program = self.prog_mut();

        match program {
            programs::Program::TracePoint(p) => {
                p.unload()?;
            }
            programs::Program::KProbe(p) => {
                p.unload()?;
            }
            programs::Program::Lsm(p) => {
                p.unload()?;
            }
            _ => {
                unimplemented!()
            }
        }
        self.loaded = false;
        self.attached = false;
        Ok(())
    }

    pub fn attach(&mut self) -> Result<(), Error> {
        let program_name = self.name.clone();
        let kernel_attach_fn = self.attach_point();
        let tracepoint_category = self.tracepoint_category();
        let program = self.prog_mut();

        match program {
            programs::Program::TracePoint(p) => {
                let cat = tracepoint_category.ok_or(Error::NoTpCategory(program_name.clone()))?;
                let attach = kernel_attach_fn.ok_or(Error::NoAttachFn(program_name))?;
                self.link_id = Some(LinkId::Tracepoint(p.attach(&cat, &attach)?));
            }
            programs::Program::KProbe(p) => {
                let attach = kernel_attach_fn.ok_or(Error::NoAttachFn(program_name))?;
                self.link_id = Some(LinkId::KProbe(p.attach(attach, 0)?));
            }
            programs::Program::Lsm(p) => {
                self.link_id = Some(LinkId::Lsm(p.attach()?));
            }
            _ => {
                unimplemented!()
            }
        }
        self.attached = true;
        Ok(())
    }

    pub fn load_and_attach(&mut self, btf: &Btf) -> Result<(), Error> {
        self.load(btf)?;
        self.attach()
    }

    pub fn detach(&mut self) -> Result<(), Error> {
        if let Some(link_id) = self.link_id.take() {
            match self.prog_mut() {
                programs::Program::TracePoint(p) => p.detach(link_id.try_into()?)?,
                programs::Program::KProbe(p) => p.detach(link_id.try_into()?)?,
                programs::Program::Lsm(p) => p.detach(link_id.try_into()?)?,
                _ => {
                    unimplemented!()
                }
            }
        }
        self.attached = false;
        Ok(())
    }
}

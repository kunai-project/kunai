use aya::{
    programs::{self, CgroupSkbAttachType, ProgramError},
    Bpf, Btf,
};
use aya_obj::generated::bpf_prog_type;
use kunai_common::version::KernelVersion;

use std::collections::HashMap;

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
                let prog = Program::from_program(name.to_string(), p);
                (name.to_string(), prog)
            })
            .collect();

        Self { m }
    }

    pub fn program_names(&self) -> Vec<&String> {
        self.m.keys().collect()
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
    pub compat: Compatibility,
    pub program: &'a mut programs::Program,
    pub enable: bool,
}

impl<'a> Program<'a> {
    pub fn from_program(name: String, p: &'a mut programs::Program) -> Self {
        Program {
            prio: 50,
            name,
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
                let (cat, name) = Self::tp_cat_name(&self.name);
                if cat == "syscalls" && name.starts_with("sys_exit") {
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

    #[inline(always)]
    // gets tracepoint category and name out of program name
    fn tp_cat_name(name: &str) -> (String, String) {
        let v: Vec<String> = name.split('.').map(|s| String::from(s)).collect();
        let cat = v.get(v.len() - 2).expect("category is missing");
        let name = v.last().expect("name is missing");
        (cat.into(), name.into())
    }

    #[inline(always)]
    // gets tracepoint category and name out of program name
    fn fn_name(name: &str) -> String {
        let v: Vec<String> = name.split('.').map(|s| String::from(s)).collect();
        v.last().expect("we must have at least one element").into()
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

    pub fn attach(&mut self, btf: &Btf) -> Result<(), ProgramError> {
        let name = self.name.clone();
        let program = self.prog_mut();

        match program {
            programs::Program::TracePoint(program) => {
                program.load()?;
                let (cat, name) = Self::tp_cat_name(&name);
                program.attach(&cat, &name)?;
            }
            programs::Program::KProbe(program) => {
                program.load()?;
                program.attach(&Self::fn_name(&name), 0)?;
            }
            programs::Program::FEntry(program) => {
                program.load(&Self::fn_name(&name), btf)?;
                program.attach()?;
            }

            programs::Program::FExit(program) => {
                program.load(&Self::fn_name(&name), btf)?;
                program.attach()?;
            }

            programs::Program::CgroupSkb(program) => {
                let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
                program.load()?;
                program.attach(cgroup, CgroupSkbAttachType::Egress)?;
            }
            _ => {
                unimplemented!()
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_kernel_macro() {
        assert_eq!(kernel!(5), KernelVersion::new(5, 0, 0));
        assert_eq!(kernel!(5, 4), KernelVersion::new(5, 4, 0));
        assert_eq!(kernel!(5, 4, 42), KernelVersion::new(5, 4, 42));
        assert!(kernel!(6) > kernel!(5, 9));
        assert!(kernel!(4, 0, 3) < kernel!(5, 9));
    }

    #[test]
    fn test_parse_kernel_version() {
        let v5 = KernelVersion::from_str("5.1.0").unwrap();
        let v6 = KernelVersion::from_str("6.1.0").unwrap();
        KernelVersion::from_str("6.0").unwrap();
        assert_eq!(
            KernelVersion::from_str("6"),
            Err(KernelVersionError::MinorIsMissing)
        );
        assert_eq!(
            KernelVersion::from_str(""),
            Err(KernelVersionError::MajorIsMissing)
        );
        assert_eq!(v5, KernelVersion::from_str("5.1.0").unwrap());
        assert!(v6 > v5);
        assert!(
            KernelVersion::from_str("5.1.1").unwrap() > KernelVersion::from_str("5.1.0").unwrap()
        );
        assert!(
            KernelVersion::from_str("5.2.1").unwrap() > KernelVersion::from_str("5.1.0").unwrap()
        );
    }

    #[test]
    fn test_from_sys() {
        println!(
            "current kernel version: {}",
            KernelVersion::from_sys().unwrap()
        );
    }
}

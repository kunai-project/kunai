use std::{
    fs, io,
    marker::PhantomPinned,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Mutex,
};

/// yara-x uses a lot of lifetimes, which makes it hard to integrate
/// in existing code. So this module mainly redefines easier types
/// to work with.
/// Wraps a yara_x::Rules, but preventing it from moving around in memory.
struct PinnedRules {
    rules: yara_x::Rules,
    _pin: PhantomPinned,
}

/// Yara-x Scanner wrapper owning its own Rules and
/// preventing some lifetime related issues
pub struct Scanner<'a> {
    scanner: Mutex<yara_x::Scanner<'a>>,
    // This allows MyScanner to own the yara_x::Rules and pass a reference to the
    // scanner. The use of `Pin` guarantees that the rules won't be moved.
    _rules: Pin<Box<PinnedRules>>,
}

pub struct SourceCode {
    content: String,
    path: PathBuf,
    _pin: PhantomPinned,
}

impl SourceCode {
    pub fn from_rule_file<P: AsRef<Path>>(p: P) -> Result<Self, io::Error> {
        Ok(SourceCode {
            content: fs::read_to_string(&p)?,
            path: p.as_ref().to_path_buf(),
            _pin: PhantomPinned,
        })
    }

    pub fn to_native(&self) -> yara_x::SourceCode<'_> {
        yara_x::SourceCode::from(self.content.as_str()).with_origin(self.path.to_string_lossy())
    }
}

impl Scanner<'_> {
    pub fn with_rules(rules: yara_x::Rules) -> Self {
        let pinned_rules = Box::pin(PinnedRules {
            rules,
            _pin: PhantomPinned,
        });
        let rules_ptr = std::ptr::from_ref(&pinned_rules.rules);
        let rules_ref = unsafe { rules_ptr.as_ref().unwrap() };
        let scanner = yara_x::Scanner::new(rules_ref);

        Self {
            scanner: scanner.into(),
            _rules: pinned_rules,
        }
    }
}

unsafe impl Send for Scanner<'_> {}

impl<'s> Deref for Scanner<'s> {
    type Target = Mutex<yara_x::Scanner<'s>>;
    fn deref(&self) -> &Self::Target {
        &self.scanner
    }
}

impl DerefMut for Scanner<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.scanner
    }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use super::{Scanner, SourceCode};

    #[test]
    fn test_scanner() {
        let mut c = yara_x::Compiler::new();
        // Add some YARA source code to compile.
        c.add_source(
            r#"
    rule lorem_ipsum {
      strings:
        $ = "Lorem ipsum"
      condition:
        all of them
    }
"#,
        )
        .unwrap();
        let s = Scanner::with_rules(c.build());
        s.lock().unwrap().scan(b"Lorem ipsum").unwrap();
    }

    #[test]
    fn test_source() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();

        tmp.write_all(
            r#"
    rule lorem_ipsum {
      strings:
        $ = "Lorem ipsum"
      condition:
        all of them
    }
"#
            .as_bytes(),
        )
        .unwrap();

        let s = SourceCode::from_rule_file(tmp.path()).unwrap();

        assert_eq!(s.path, tmp.path().to_path_buf());

        let mut c = yara_x::Compiler::new();

        // Add some YARA source code to compile.
        c.add_source(s.to_native()).unwrap();

        let s = Scanner::with_rules(c.build());
        s.lock().unwrap().scan(b"Lorem ipsum").unwrap();
    }
}

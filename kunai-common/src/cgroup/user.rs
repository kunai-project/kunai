
    use std::fmt;

    use super::Cgroup;

    impl Cgroup {
        pub fn to_vec(&self) -> Vec<String> {
            self.path.to_string().split('/').map(|s| s.to_string()).rev().collect()
        }
    }

    impl fmt::Display for Cgroup {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.to_vec().join("/"))
        }
    }
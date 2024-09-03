use std::env::VarError;

pub(crate) fn vec_rustflags() -> Result<Vec<String>, anyhow::Error> {
    match std::env::var("RUSTFLAGS") {
        Ok(s) => Ok(vec![s]),
        Err(e) => match e {
            VarError::NotPresent => Ok(vec![]),
            _ => Err(e.into()),
        },
    }
}

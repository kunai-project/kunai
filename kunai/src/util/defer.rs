pub struct Defer<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> From<F> for Defer<F> {
    fn from(value: F) -> Self {
        Self(Some(value))
    }
}

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

macro_rules! defer {
    ($fn_once:expr) => {
        let _defer = $crate::util::defer::Defer::from($fn_once);
    };
}

pub(crate) use defer;

#[cfg(test)]
mod test {
    use crate::util::defer::{defer, Defer};

    #[test]
    fn test_defer() {
        defer!(|| { println!("test") });

        let _defer = Defer(Some(|| {
            println!("This is deferred and will run when the scope ends!");
        }));

        println!("Doing some work...");
    }
}

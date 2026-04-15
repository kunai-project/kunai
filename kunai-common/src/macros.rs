#[macro_export]
/// inspect_err(expr, closure)
/// calls closure if the result of expr is an Err
macro_rules! inspect_err {
    ($e:expr, $clos:expr) => {{
        let res = $e;
        if let Err(e) = res.as_ref() {
            $clos(e);
        }
        res
    }};
}

macro_rules! test_flag {
    ($test:expr, $flag:literal) => {
        $test & $flag == $flag
    };
}

pub(crate) use test_flag;

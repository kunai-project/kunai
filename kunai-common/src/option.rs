#[repr(C)]
#[derive(Debug, Default)]
pub enum BpfOption<T> {
    Some(T),
    #[default]
    None,
}

impl<T> From<Option<T>> for BpfOption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(t) => Self::Some(t),
            None => Self::None,
        }
    }
}

impl<T> From<BpfOption<T>> for Option<T> {
    fn from(value: BpfOption<T>) -> Self {
        match value {
            BpfOption::Some(t) => Some(t),
            BpfOption::None => None,
        }
    }
}

impl<T> Clone for BpfOption<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        self.as_ref().map(|t| t.clone())
    }
}

impl<T> Copy for BpfOption<T> where T: Copy {}

impl<T> PartialEq for BpfOption<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Some(a), Self::Some(b)) => a == b,
            (Self::None, Self::None) => true,
            _ => false,
        }
    }
}

impl<T> Eq for BpfOption<T> where T: Eq {}

impl<T> BpfOption<T> {
    #[inline]
    pub fn map<U, F>(self, f: F) -> BpfOption<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            BpfOption::Some(t) => BpfOption::Some(f(t)),
            BpfOption::None => BpfOption::None,
        }
    }

    #[inline]
    pub const fn as_ref(&self) -> BpfOption<&T> {
        match self {
            BpfOption::Some(t) => BpfOption::Some(t),
            BpfOption::None => BpfOption::None,
        }
    }

    #[inline]
    pub const fn as_mut(&mut self) -> BpfOption<&mut T> {
        match self {
            BpfOption::Some(t) => BpfOption::Some(t),
            BpfOption::None => BpfOption::None,
        }
    }

    #[inline]
    pub fn into_opt(self) -> Option<T> {
        self.into()
    }

    pub fn unwrap_or_default(self) -> T
    where
        T: Default,
    {
        match self {
            BpfOption::Some(t) => t,
            BpfOption::None => T::default(),
        }
    }
}

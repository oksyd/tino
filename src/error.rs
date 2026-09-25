use std::error::Error as StdError;
use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    message: String,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    usage: bool,
}

impl Error {
    #[must_use]
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
            usage: false,
        }
    }

    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
            usage: true,
        }
    }

    /// Returns the binary's exit code for this error: 2 for invalid usage,
    /// or 1 for other failures. Context wrappers preserve this distinction.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.usage {
            return 2;
        }
        let mut source = self.source();
        while let Some(err) = source {
            if err.downcast_ref::<Self>().is_some_and(|err| err.usage) {
                return 2;
            }
            source = err.source();
        }
        1
    }

    #[must_use]
    pub fn with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
            usage: false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if f.alternate() {
            let mut source = self.source();
            while let Some(err) = source {
                write!(f, "\ncaused by: {err}")?;
                source = err.source();
            }
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::msg(value.to_string())
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(value: std::ffi::NulError) -> Self {
        Self::msg(value.to_string())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::msg(value.to_string())
    }
}

#[cfg(target_os = "linux")]
impl From<crate::platform::unix::sys::Errno> for Error {
    fn from(value: crate::platform::unix::sys::Errno) -> Self {
        Self::msg(value.to_string())
    }
}

pub trait Context<T> {
    fn context(self, message: impl Into<String>) -> Result<T>;

    fn with_context<M>(self, f: impl FnOnce() -> M) -> Result<T>
    where
        M: Into<String>;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|err| Error::with_source(message, err))
    }

    fn with_context<M>(self, f: impl FnOnce() -> M) -> Result<T>
    where
        M: Into<String>,
    {
        self.map_err(|err| Error::with_source(f(), err))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| Error::msg(message))
    }

    fn with_context<M>(self, f: impl FnOnce() -> M) -> Result<T>
    where
        M: Into<String>,
    {
        self.ok_or_else(|| Error::msg(f()))
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::Error::msg(format!($($arg)*))
    };
}

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_survives_nested_context() {
        for (error, expected) in [
            (Error::usage("bad option combination"), 2),
            (Error::msg("supervision failed"), 1),
        ] {
            let result: Result<()> = Err(error);
            let error = result.context("inner").context("outer").unwrap_err();
            assert_eq!(error.exit_code(), expected);
        }
        let result: std::io::Result<()> = Err(std::io::Error::from_raw_os_error(13));
        assert_eq!(result.context("open file").unwrap_err().exit_code(), 1);
    }
}

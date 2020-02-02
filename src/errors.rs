use std::fmt;

macro_rules! wrap_error {
    ($message:expr,$err:expr) => {
        return Error::wrap($message, Box::new($err));
    };
}

#[derive(Debug)]
pub struct Error {
    src: Option<Box<dyn std::error::Error + 'static + Send + Sync>>,
    message: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn new(message: &str) -> Self {
        Self {
            src: None,
            message: message.to_string(),
        }
    }

    pub fn wrap(message: &str, err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self {
            src: Some(err),
            message: message.to_owned(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.src {
            Some(source) => write!(f, "{}: {}", self.message, source),
            None => write!(f, "{}", self.message),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self {
            src: Some(Box::new(err)),
            message: "IO error".to_string(),
        }
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self {
            src: None,
            message: err.to_string(),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self {
            src: None,
            message: err,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self {
            src: Some(Box::new(err)),
            message: "Error decoding JSON".into(),
        }
    }
}

impl Into<std::io::Error> for Error {
    fn into(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.src {
            Some(ref source) => Some(&**source),
            None => None,
        }
    }
}

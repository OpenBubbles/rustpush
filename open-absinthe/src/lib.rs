use std::{error::Error, fmt::Display};

pub mod nac;

#[derive(Debug)]
pub struct AbsintheError(i32);

impl Display for AbsintheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for AbsintheError { }
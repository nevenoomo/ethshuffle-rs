//! # Errors
//!
//! Error messages to be used in the protocol

use super::peers::AccountNum;
use std::io::{Error, ErrorKind};

pub(crate) fn incorrect_session_number(session_id: u64, blame_acc: &AccountNum) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!(
            "peer used incorrect session number {}\nBlame account number: {:x?}",
            session_id, blame_acc
        ),
    )
}

pub(crate) fn impersonalisation(blame_acc: &AccountNum) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("impersonalisation attempt by {:x?}", blame_acc),
    )
}

pub(crate) fn signature_invalid(blame_acc: &AccountNum) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!(
            "signature is invalid\nBlame account number: {:x?}",
            blame_acc
        ),
    )
}

pub(crate) fn could_not_verify_signature<E: std::fmt::Display>(
    due_error: E,
    blame_acc: &AccountNum,
) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!(
            "signature validation failed: {}\nBlame account number: {:x?}",
            due_error, blame_acc
        ),
    )
}

pub(crate) fn equivocation_attempt(blame_acc: &AccountNum) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("equivocation attempt by {:x?}", blame_acc),
    )
}
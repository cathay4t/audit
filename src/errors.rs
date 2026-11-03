// SPDX-License-Identifier: MIT

use std::fmt;

use netlink_packet_core::{ErrorMessage, NetlinkMessage};
use netlink_proto::NetlinkProtoError;

use crate::packet::AuditMessage;

#[derive(Debug)]
pub enum AuditError {
    UnexpectedMessage(NetlinkMessage<AuditMessage>),

    NetlinkError(ErrorMessage),

    /// The request stream ended without any response.
    NoMessageReceived,

    /// Netlink socket level error.
    NetlinkProtoError(NetlinkProtoError),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedMessage(msg) => {
                write!(f, "Received an unexpected message {msg:?}")
            }
            Self::NetlinkError(err) => {
                write!(f, "Received a netlink error message {err:?}")
            }
            Self::NoMessageReceived => {
                write!(f, "No message received")
            }
            Self::NetlinkProtoError(err) => {
                write!(f, "Netlink socket error: {err}")
            }
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NetlinkProtoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<NetlinkProtoError> for AuditError {
    fn from(err: NetlinkProtoError) -> Self {
        match err {
            // Kernel errors encoded in the netlink packet are handled
            // natively by this crate.
            NetlinkProtoError::NetlinkError(err_msg) => {
                Self::NetlinkError(err_msg)
            }
            // Socket level errors are kept as is.
            other => Self::NetlinkProtoError(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use netlink_packet_core::ErrorMessage;
    use netlink_proto::NetlinkProtoError;

    use super::AuditError;

    #[test]
    fn kernel_error_is_handled_natively() {
        let err = AuditError::from(NetlinkProtoError::NetlinkError(
            ErrorMessage::default(),
        ));
        assert!(matches!(err, AuditError::NetlinkError(_)));
    }

    #[test]
    fn socket_level_error_is_kept_wrapped() {
        let err = AuditError::from(NetlinkProtoError::ConnectionClosed);
        assert!(matches!(
            err,
            AuditError::NetlinkProtoError(NetlinkProtoError::ConnectionClosed)
        ));

        let err = AuditError::from(NetlinkProtoError::SocketIo(
            io::Error::new(io::ErrorKind::BrokenPipe, "test"),
        ));
        assert!(matches!(
            err,
            AuditError::NetlinkProtoError(NetlinkProtoError::SocketIo(_))
        ));
    }
}

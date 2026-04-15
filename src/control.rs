//! Unix socket control listener for CLI commands.
//!
//! Protocol: `[4-byte LE length][JSON payload]`
//! Used by the CLI to query status, ban/unban IPs, and trigger reloads.

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::error::{Error, Result};

/// Commands from the CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Get overall status.
    Status,
    /// List all active bans.
    ListBans,
    /// Ban an IP in a specific jail.
    Ban { ip: IpAddr, jail: String },
    /// Unban an IP from a specific jail.
    Unban { ip: IpAddr, jail: String },
    /// Reload configuration.
    Reload,
    /// Get daemon statistics.
    Stats,
}

/// Response from the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self::Ok {
            message: Some(message.into()),
            data: None,
        }
    }

    pub fn ok_data(data: serde_json::Value) -> Self {
        Self::Ok {
            message: None,
            data: Some(data),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// A control command with a response channel.
pub struct ControlCmd {
    pub request: Request,
    pub respond: oneshot::Sender<Response>,
}

/// Run the control socket listener.
pub async fn run(socket_path: &Path, tx: mpsc::Sender<ControlCmd>, cancel: CancellationToken) {
    // Remove stale socket file.
    let _ = std::fs::remove_file(socket_path);

    // Ensure parent directory exists with restricted permissions.
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750));
        }
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            error!(
                phase = "startup",
                path = %socket_path.display(),
                error = %e,
                "control socket bind failed"
            );
            return;
        }
    };

    // Restrict socket to owner+group (prevent other local users from connecting).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
        {
            warn!(
                phase = "startup",
                error = %e,
                "control socket permissions failed"
            );
        }
    }

    info!(
        phase = "startup",
        path = %socket_path.display(),
        "control socket listening"
    );

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                info!(phase = "shutdown", "control socket stopping");
                let _ = std::fs::remove_file(socket_path);
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, tx).await {
                                warn!(error = %e, "control connection error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "accept error");
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    tx: mpsc::Sender<ControlCmd>,
) -> Result<()> {
    // Read length prefix.
    let len = stream
        .read_u32_le()
        .await
        .map_err(|e| Error::protocol(format!("read length: {e}")))?;

    if len > 1024 * 64 {
        return Err(Error::protocol(format!("message too large: {len}")));
    }

    // Read JSON payload.
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read payload: {e}")))?;

    let request: Request =
        serde_json::from_slice(&buf).map_err(|e| Error::protocol(format!("parse request: {e}")))?;

    // Send to handler and wait for response.
    let (resp_tx, resp_rx) = oneshot::channel();
    let cmd = ControlCmd {
        request,
        respond: resp_tx,
    };

    tx.send(cmd)
        .await
        .map_err(|_| Error::protocol("handler channel closed"))?;

    let response = resp_rx
        .await
        .map_err(|_| Error::protocol("response channel dropped"))?;

    // Write response.
    let json = serde_json::to_vec(&response)
        .map_err(|e| Error::protocol(format!("serialize response: {e}")))?;
    stream
        .write_u32_le(json.len() as u32)
        .await
        .map_err(|e| Error::protocol(format!("write length: {e}")))?;
    stream
        .write_all(&json)
        .await
        .map_err(|e| Error::protocol(format!("write payload: {e}")))?;

    Ok(())
}

/// Send a request to the daemon control socket and return the response.
pub async fn send_request(socket_path: &Path, request: &Request) -> Result<Response> {
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| Error::protocol(format!("connect to {}: {e}", socket_path.display())))?;

    let json = serde_json::to_vec(request)
        .map_err(|e| Error::protocol(format!("serialize request: {e}")))?;

    stream
        .write_u32_le(json.len() as u32)
        .await
        .map_err(|e| Error::protocol(format!("write length: {e}")))?;
    stream
        .write_all(&json)
        .await
        .map_err(|e| Error::protocol(format!("write payload: {e}")))?;

    let len = stream
        .read_u32_le()
        .await
        .map_err(|e| Error::protocol(format!("read response length: {e}")))?;

    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| Error::protocol(format!("read response: {e}")))?;

    let response: Response = serde_json::from_slice(&buf)
        .map_err(|e| Error::protocol(format!("parse response: {e}")))?;

    Ok(response)
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod tests {
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use crate::control::{self, ControlCmd, Request, Response};

    #[tokio::test]
    async fn request_response_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let (tx, mut rx) = mpsc::channel::<ControlCmd>(16);
        let cancel = CancellationToken::new();

        let sock = sock_path.clone();
        let cancel_clone = cancel.clone();
        let server = tokio::spawn(async move {
            control::run(&sock, tx, cancel_clone).await;
        });

        // Give server time to bind.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Spawn a handler that responds to Status requests.
        let handler = tokio::spawn(async move {
            if let Some(cmd) = rx.recv().await {
                match cmd.request {
                    Request::Status => {
                        let _ = cmd.respond.send(Response::ok("running"));
                    }
                    _ => {
                        let _ = cmd.respond.send(Response::error("unexpected"));
                    }
                }
            }
        });

        // Send a status request.
        let response = control::send_request(&sock_path, &Request::Status)
            .await
            .unwrap();

        match response {
            Response::Ok { message, .. } => {
                assert_eq!(message.unwrap(), "running");
            }
            Response::Error { message } => panic!("unexpected error: {message}"),
        }

        cancel.cancel();
        handler.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ban_request_serialization() {
        let req = Request::Ban {
            ip: "1.2.3.4".parse().unwrap(),
            jail: "sshd".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("ban"));
        assert!(json.contains("1.2.3.4"));

        let parsed: Request = serde_json::from_str(&json).unwrap();
        match parsed {
            Request::Ban { ip, jail } => {
                assert_eq!(ip.to_string(), "1.2.3.4");
                assert_eq!(jail, "sshd");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn unban_request_serialization() {
        let req = Request::Unban {
            ip: "10.0.0.1".parse().unwrap(),
            jail: "nginx".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        match parsed {
            Request::Unban { ip, jail } => {
                assert_eq!(ip.to_string(), "10.0.0.1");
                assert_eq!(jail, "nginx");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn connect_to_nonexistent_socket() {
        let result = control::send_request(
            std::path::Path::new("/tmp/nonexistent-fail2ban-rs-test.sock"),
            &Request::Status,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("connect"), "got: {err}");
    }

    #[tokio::test]
    async fn all_request_variants_through_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let (tx, mut rx) = mpsc::channel::<ControlCmd>(16);
        let cancel = CancellationToken::new();

        let sock = sock_path.clone();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            control::run(&sock, tx, cancel_clone).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Handler that responds to everything.
        let handler = tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let response = match cmd.request {
                    Request::Status => Response::ok("up"),
                    Request::ListBans => Response::ok_data(serde_json::json!({"bans": []})),
                    Request::Ban { ip, jail } => Response::ok(format!("banned {ip} in {jail}")),
                    Request::Unban { ip, jail } => {
                        Response::ok(format!("unbanned {ip} from {jail}"))
                    }
                    Request::Reload => Response::ok("reloaded"),
                    Request::Stats => Response::ok_data(serde_json::json!({"uptime": 42})),
                };
                let _ = cmd.respond.send(response);
            }
        });

        // Test each variant.
        let resp = control::send_request(&sock_path, &Request::Status)
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }));

        let resp = control::send_request(&sock_path, &Request::ListBans)
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }));

        let resp = control::send_request(
            &sock_path,
            &Request::Ban {
                ip: "1.2.3.4".parse().unwrap(),
                jail: "sshd".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(resp, Response::Ok { .. }));

        let resp = control::send_request(
            &sock_path,
            &Request::Unban {
                ip: "1.2.3.4".parse().unwrap(),
                jail: "sshd".to_string(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(resp, Response::Ok { .. }));

        let resp = control::send_request(&sock_path, &Request::Reload)
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }));

        cancel.cancel();
        handler.abort();
    }

    #[test]
    fn response_ok_data_has_no_message() {
        let data = serde_json::json!({"count": 5});
        let resp = Response::ok_data(data);
        let json = serde_json::to_string(&resp).unwrap();
        // message should be absent (skip_serializing_if).
        assert!(!json.contains("message"), "got: {json}");
        assert!(json.contains("count"));
    }

    #[test]
    fn reload_request_serialization() {
        let req = Request::Reload;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::Reload));
    }

    #[test]
    fn list_bans_request_serialization() {
        let req = Request::ListBans;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Request::ListBans));
    }
}

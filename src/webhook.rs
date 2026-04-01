//! Webhook notification on ban events.
//!
//! Fires a non-blocking HTTP POST via `curl` subprocess. Webhook failures
//! never affect the ban pipeline — errors are logged and discarded.

use std::net::IpAddr;

use tracing::warn;

/// Fire a webhook notification for a ban event.
///
/// Spawns a `curl` subprocess in the background. Returns immediately.
pub fn notify_ban(url: &str, ip: IpAddr, jail: &str, ban_time: i64) {
    let payload = serde_json::json!({
        "event": "ban",
        "ip": ip.to_string(),
        "jail": jail,
        "ban_time": ban_time,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let body = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "webhook: failed to serialize payload");
            return;
        }
    };

    let url = url.to_string();
    tokio::spawn(async move {
        let result = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-m",
                "10",
                "-d",
                &body,
                &url,
            ])
            .output()
            .await;

        match result {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(url = %url, stderr = %stderr, "webhook POST failed");
            }
            Err(e) => {
                warn!(url = %url, error = %e, "webhook: curl not available");
            }
            _ => {}
        }
    });
}

/// Fire a webhook notification for an unban event.
pub fn notify_unban(url: &str, ip: IpAddr, jail: &str) {
    let payload = serde_json::json!({
        "event": "unban",
        "ip": ip.to_string(),
        "jail": jail,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let body = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "webhook: failed to serialize payload");
            return;
        }
    };

    let url = url.to_string();
    tokio::spawn(async move {
        let result = tokio::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-m",
                "10",
                "-d",
                &body,
                &url,
            ])
            .output()
            .await;

        if let Err(e) = result {
            warn!(url = %url, error = %e, "webhook: curl not available");
        }
    });
}

#[cfg(test)]
mod tests {
    // Webhook functions spawn tokio tasks that call curl, so we can only
    // test that they don't panic. The actual HTTP POST is not tested here
    // (would need a test server).

    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn notify_ban_does_not_panic() {
        // Use an invalid URL — the curl call will fail, but it should
        // not panic or block.
        crate::webhook::notify_ban(
            "http://127.0.0.1:1/test",
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            "sshd",
            3600,
        );
        // Give the spawned task a moment to run.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn notify_unban_does_not_panic() {
        crate::webhook::notify_unban(
            "http://127.0.0.1:1/test",
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            "nginx",
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

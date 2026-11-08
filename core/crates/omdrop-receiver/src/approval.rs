//! Bounded desktop consent. Peer text is never evaluated as a command.
use omdrop_proto::archive::is_unsafe_char;
use plist::{Dictionary, Value};
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn required(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(value) => value.trim() != "auto",
        Err(e) => e.kind() != io::ErrorKind::NotFound,
    }
}
fn text(value: Option<&str>) -> String {
    let text: String = value
        .unwrap_or("Unknown device")
        .chars()
        .take(160)
        .filter(|&c| !is_unsafe_char(c) || c == '/' || c == '\\')
        .collect();
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
pub fn request(ask: &Dictionary) -> bool {
    let sender = text(ask.get("SenderComputerName").and_then(Value::as_string));
    let mut names: Vec<String> = ask
        .get("Files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(3)
        .map(|f| {
            text(
                f.as_dictionary()
                    .and_then(|d| d.get("FileName"))
                    .and_then(Value::as_string),
            )
        })
        .collect();
    if names.is_empty() {
        names = ask
            .get("Items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(3)
            .map(|v| text(v.as_string()))
            .collect();
    }
    prompt(
        "notify-send",
        &format!("{sender}\n{}", names.join(", ")),
        Duration::from_secs(30),
    )
}
fn prompt(program: &str, description: &str, timeout: Duration) -> bool {
    let Ok(mut child) = Command::new(program)
        .args([
            "--wait",
            "--print-id",
            "--urgency=critical",
            "--expire-time=30000",
            "--app-name=Omdrop",
            "--action=reject=Decline",
            "--action=accept=Accept",
            "--",
            "AirDrop request",
            description,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let mut output = String::new();
    if let Some(stdout) = child.stdout.take() {
        let _ = stdout.take(128).read_to_string(&mut output);
    }
    let mut lines = output.lines();
    let id = lines.next().unwrap_or_default();
    let accepted = success && lines.next() == Some("accept") && lines.next().is_none();
    // Critical notifications may ignore their expiration. Close explicitly;
    // late actions cannot grant approval to another request.
    if id.parse::<u32>().is_ok() {
        let _ = Command::new("busctl")
            .args([
                "--user",
                "--timeout=2s",
                "call",
                "org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
                "CloseNotification",
                "u",
                id,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    accepted
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn mode_is_opt_in_and_invalid_settings_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receive-mode");
        assert!(!required(&path));
        for value in ["ask", "broken", ""] {
            std::fs::write(&path, value).unwrap();
            assert!(required(&path));
        }
        std::fs::write(&path, "auto\n").unwrap();
        assert!(!required(&path));
    }
    #[test]
    fn markup_and_control_characters_are_neutralised() {
        let shown = text(Some("<img src='x'>\u{202e}\n"));
        assert!(!shown.contains("<img"));
        assert!(shown.contains("&lt;img"));
        assert!(!shown.contains('\u{202e}'));
    }
    #[test]
    fn only_explicit_accept_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        for (response, expected) in [
            ("accept", true),
            ("reject", false),
            ("default", false),
            ("", false),
        ] {
            std::fs::write(
                &path,
                format!("#!/bin/sh\nprintf 'not-an-id\\n{response}\\n'\n"),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                prompt(path.to_str().unwrap(), "test", Duration::from_secs(1)),
                expected
            );
        }
        assert!(!prompt(
            "/nonexistent/notify",
            "test",
            Duration::from_millis(1)
        ));
    }
    #[test]
    fn timeout_kills_and_reaps_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        std::fs::write(&path, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let before = Instant::now();
        assert!(!prompt(
            path.to_str().unwrap(),
            "test",
            Duration::from_millis(50)
        ));
        assert!(before.elapsed() < Duration::from_secs(2));
    }
}

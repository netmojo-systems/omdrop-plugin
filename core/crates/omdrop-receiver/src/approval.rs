//! Bounded desktop consent. Peer text is never evaluated as a command.
use omdrop_proto::{archive::is_unsafe_char, receive_answer};
use plist::{Dictionary, Value};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
fn links(ask: &Dictionary) -> bool {
    match ask.get("TransferType") {
        Some(Value::Dictionary(types)) => types.contains_key("links"),
        Some(Value::Array(types)) => types.iter().any(|v| v.as_string() == Some("links")),
        _ => false,
    }
}
fn description(ask: &Dictionary) -> String {
    let sender = text(ask.get("SenderComputerName").and_then(Value::as_string));
    let empty = Vec::new();
    let (count, summary, names) = if links(ask) {
        let urls: Vec<&str> = ask
            .get("Items")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .filter_map(Value::as_string)
            .filter(|url| {
                (url.starts_with("https://") || url.starts_with("http://"))
                    && url.len() <= crate::server::MAX_LINK_URL_BYTES
                    && !url.chars().any(|c| c.is_whitespace() || c.is_control())
            })
            .collect();
        let names: Vec<String> = urls
            .iter()
            .take(3)
            .map(|url| {
                // Show the actual destinations, never unrelated Files metadata.
                let authority = url
                    .split_once("://")
                    .unwrap()
                    .1
                    .split(['/', '?', '#'])
                    .next()
                    .unwrap_or("");
                text(Some(authority.rsplit('@').next().unwrap_or("")))
            })
            .collect();
        (urls.len(), format!("{} link(s)", urls.len()), names)
    } else {
        let files = ask.get("Files").and_then(Value::as_array).unwrap_or(&empty);
        let size = files.iter().try_fold(0u64, |sum, f| {
            sum.checked_add(f.as_dictionary()?.get("FileSize")?.as_unsigned_integer()?)
        });
        let summary = match size {
            Some(n) if n >= 1_048_576 => format!(
                "{} file(s), {:.1} MiB reported",
                files.len(),
                n as f64 / 1_048_576.0
            ),
            Some(n) if n >= 1024 => format!(
                "{} file(s), {:.1} KiB reported",
                files.len(),
                n as f64 / 1024.0
            ),
            Some(n) => format!("{} file(s), {n} bytes reported", files.len()),
            None => format!("{} file(s), size unknown", files.len()),
        };
        let names = files
            .iter()
            .take(3)
            .map(|f| {
                text(
                    f.as_dictionary()
                        .and_then(|d| d.get("FileName"))
                        .and_then(Value::as_string),
                )
            })
            .collect();
        (files.len(), summary, names)
    };
    let more = count.saturating_sub(names.len());
    let suffix = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    format!("From {sender}\n{summary}\n{}{suffix}", names.join(", "))
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|p| p.join(name))
        .find(|p| std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0))
}
enum Backend {
    Omarchy {
        program: PathBuf,
        answer_command: PathBuf,
    },
    Standard {
        program: PathBuf,
    },
}

pub fn request(ask: &Dictionary, cancelled: &dyn Fn() -> bool) -> bool {
    let backend = if let Some(program) = which("omarchy-notification-send") {
        let Some(answer_command) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("omdrop")))
        else {
            return false;
        };
        Backend::Omarchy {
            program,
            answer_command,
        }
    } else {
        Backend::Standard {
            program: PathBuf::from("notify-send"),
        }
    };
    prompt(
        &backend,
        &description(ask),
        Duration::from_secs(30),
        cancelled,
        &receive_answer::directory(),
    )
}

struct Reply {
    socket: UnixDatagram,
    path: PathBuf,
    token: String,
}
impl Reply {
    fn new(directory: &Path) -> io::Result<Self> {
        receive_answer::private_directory(directory, true)?;
        let mut random = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = receive_answer::socket_path(directory, &token)?;
        let socket = UnixDatagram::bind(&path)?;
        let reply = Self {
            socket,
            path,
            token,
        };
        std::fs::set_permissions(&reply.path, std::fs::Permissions::from_mode(0o600))?;
        reply.socket.set_nonblocking(true)?;
        Ok(reply)
    }
    fn answer(&self) -> Option<bool> {
        let mut bytes = [0u8; 16];
        match self.socket.recv(&mut bytes) {
            Ok(n) => Some(&bytes[..n] == b"accept"),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => Some(false),
        }
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn drain(child: &mut Child, output: &mut Vec<u8>) -> io::Result<()> {
    if let Some(stdout) = &mut child.stdout {
        let mut buf = [0u8; 128];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) if output.len() + n <= 128 => output.extend_from_slice(&buf[..n]),
                Ok(_) => return Err(io::Error::other("notification helper output too long")),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}
fn prompt(
    backend: &Backend,
    description: &str,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
    directory: &Path,
) -> bool {
    if cancelled() {
        return false;
    }
    let native = matches!(backend, Backend::Omarchy { .. });
    let reply = if native {
        match Reply::new(directory) {
            Ok(reply) => Some(reply),
            Err(_) => return false,
        }
    } else {
        None
    };
    let mut command = match backend {
        Backend::Omarchy {
            program,
            answer_command,
        } => {
            let mut command = Command::new(program);
            command.args([
                "-p",
                "-u",
                "critical",
                "-t",
                "30000",
                "AirDrop request",
                description,
            ]);
            for (label, answer) in [("Decline", "decline"), ("Accept", "accept")] {
                command.args(["--action", label]).arg(answer_command).args([
                    "receive-answer",
                    &reply.as_ref().unwrap().token,
                    answer,
                ]);
            }
            command
        }
        Backend::Standard { program } => {
            let mut command = Command::new(program);
            command.args([
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
            ]);
            command
        }
    };
    let Ok(mut child) = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let stdout = child.stdout.as_ref().unwrap();
    // SAFETY: stdout owns this valid fd. Nonblocking reads bound both native
    // helpers (which return immediately) and standard helpers (which wait).
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    let nonblocking = flags >= 0
        && unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0;
    let deadline = Instant::now() + timeout;
    let mut output = Vec::new();
    let accepted = loop {
        if !nonblocking
            || cancelled()
            || Instant::now() >= deadline
            || drain(&mut child, &mut output).is_err()
        {
            break false;
        }
        if let Some(answer) = reply.as_ref().and_then(Reply::answer) {
            break answer;
        }
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => break false,
            Ok(Some(_)) if !native => {
                if drain(&mut child, &mut output).is_err() {
                    break false;
                }
                let text = String::from_utf8_lossy(&output);
                let mut lines = text.lines();
                let _ = lines.next();
                break lines.next() == Some("accept") && lines.next().is_none();
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break false,
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = drain(&mut child, &mut output);
    // Native actions use one-use socket tokens, removed on every exit. A late
    // click cannot approve another transfer. Critical toasts need closing too.
    if let Some(id) = String::from_utf8_lossy(&output)
        .lines()
        .next()
        .filter(|id| id.parse::<u32>().is_ok())
    {
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
    fn helper(path: &Path, body: &str) {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
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
    fn prompt_discloses_counts_reported_size_and_actual_link_hosts() {
        let mut ask = Dictionary::new();
        ask.insert(
            "Files".into(),
            Value::Array(
                (0..12)
                    .map(|_| {
                        Value::Dictionary(Dictionary::from_iter([
                            ("FileName".to_string(), Value::String("holiday.jpg".into())),
                            ("FileSize".to_string(), Value::Integer(4_194_304.into())),
                        ]))
                    })
                    .collect(),
            ),
        );
        let shown = description(&ask);
        assert!(shown.contains("12 file(s), 48.0 MiB reported"));
        assert!(shown.contains("+9 more"));
        ask.insert(
            "TransferType".into(),
            Value::Dictionary(Dictionary::from_iter([(
                "links".to_string(),
                Value::Boolean(true),
            )])),
        );
        ask.insert(
            "Items".into(),
            Value::Array(vec![Value::String("https://unseen.example/x".into())]),
        );
        let shown = description(&ask);
        assert!(shown.contains("unseen.example"));
        assert!(!shown.contains("holiday.jpg"));
    }
    #[test]
    fn standard_backend_only_accepts_explicit_accept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let backend = Backend::Standard {
            program: path.clone(),
        };
        for (answer, accepted) in [
            ("accept", true),
            ("reject", false),
            ("default", false),
            ("", false),
        ] {
            helper(&path, &format!("printf 'not-an-id\\n{answer}\\n'"));
            assert_eq!(
                prompt(
                    &backend,
                    "test",
                    Duration::from_secs(1),
                    &|| false,
                    dir.path()
                ),
                accepted
            );
        }
        helper(&path, "printf 'not-an-id\\naccept\\n'; exit 1");
        assert!(!prompt(
            &backend,
            "test",
            Duration::from_secs(1),
            &|| false,
            dir.path()
        ));
    }
    #[test]
    fn timeout_and_cancellation_kill_and_reap_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        helper(&path, "exec sleep 30");
        let backend = Backend::Standard { program: path };
        for cancelled in [false, true] {
            let before = Instant::now();
            assert!(!prompt(
                &backend,
                "test",
                Duration::from_millis(50),
                &|| cancelled,
                dir.path()
            ));
            assert!(before.elapsed() < Duration::from_secs(2));
        }
    }
    #[test]
    fn native_timeout_and_helper_failure_remove_the_pending_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let backend = Backend::Omarchy {
            program: path.clone(),
            answer_command: PathBuf::from("/installed/omdrop"),
        };
        let requests = dir.path().join("requests");
        for body in ["printf 'not-an-id\\n'", "exit 1"] {
            helper(&path, body);
            assert!(!prompt(
                &backend,
                "test",
                Duration::from_millis(50),
                &|| false,
                &requests
            ));
            assert_eq!(std::fs::read_dir(&requests).unwrap().count(), 0);
        }
    }

    #[test]
    fn native_backend_uses_private_one_use_replies_and_default_omarchy_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let args = dir.path().join("args");
        helper(
            &path,
            &format!(
                "printf '%s\\n' \"$@\" > '{}'; printf 'not-an-id\\n'",
                args.display()
            ),
        );
        let backend = Backend::Omarchy {
            program: path,
            answer_command: PathBuf::from("/installed/omdrop"),
        };
        let requests = dir.path().join("requests");
        for (answer, expected) in [("accept", true), ("decline", false)] {
            std::thread::scope(|scope| {
                let request = scope.spawn(|| {
                    prompt(
                        &backend,
                        "test",
                        Duration::from_secs(2),
                        &|| false,
                        &requests,
                    )
                });
                let deadline = Instant::now() + Duration::from_secs(1);
                let token = loop {
                    if let Ok(entries) = std::fs::read_dir(&requests)
                        && let Some(entry) = entries.flatten().next()
                    {
                        break entry
                            .path()
                            .file_stem()
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string();
                    }
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(10));
                };
                // Wait until the notification helper has actually run.
                while !args.exists() {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(10));
                }
                receive_answer::send(&requests, &token, answer).unwrap();
                assert_eq!(request.join().unwrap(), expected);
                assert!(receive_answer::send(&requests, &token, "accept").is_err());
            });
            let wire = std::fs::read_to_string(&args).unwrap();
            assert!(!wire.contains("--app-name")); // default omarchy-action passes DND
            assert!(wire.contains("--action\nDecline\n/installed/omdrop\nreceive-answer\n"));
            assert!(wire.contains("--action\nAccept\n"));
            assert_eq!(std::fs::read_dir(&requests).unwrap().count(), 0);
            std::fs::remove_file(&args).unwrap();
        }
    }
}

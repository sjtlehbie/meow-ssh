use anyhow::Result;

pub struct ShellConfig {
    pub shell: String,
    pub shell_user: Option<String>,
    pub shell_home: Option<String>,
}

/// Spawns a PTY with a shell process. Returns (Pty, tokio::process::Child).
/// The Pty handles read/write/resize, the Child is the spawned process.
pub fn spawn_pty(
    config: &ShellConfig,
    cols: u16,
    rows: u16,
) -> Result<(pty_process::Pty, tokio::process::Child)> {
    let (pty, pts) = pty_process::open()?;
    pty.resize(pty_process::Size::new(rows, cols))?;

    let child = if let Some(ref user) = config.shell_user {
        pty_process::Command::new("sudo")
            .args(["-u", user, "-i", &config.shell])
            .env("TERM", "xterm-256color")
            .spawn(pts)?
    } else {
        let mut cmd = pty_process::Command::new(&config.shell);
        cmd = cmd.arg("-l").env("TERM", "xterm-256color");
        if let Some(ref home) = config.shell_home {
            cmd = cmd.env("HOME", home);
        }
        cmd.spawn(pts)?
    };

    Ok((pty, child))
}

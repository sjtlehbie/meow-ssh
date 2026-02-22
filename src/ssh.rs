use crate::db::Db;
use crate::pty::{self, ShellConfig};
use anyhow::Result;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodKind, MethodSet};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const CAT_ART: &str = r#"
   /\_/\
  ( o.o )  meow-ssh
   > ^ <
"#;

pub struct SshServer {
    pub db: Arc<Db>,
    pub shell_config: Arc<ShellConfig>,
    pub domain: String,
    pub web_port: u16,
}

impl russh::server::Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        SshSession {
            db: self.db.clone(),
            shell_config: self.shell_config.clone(),
            domain: self.domain.clone(),
            web_port: self.web_port,
            user_id: None,
            token: None,
            cols: 80,
            rows: 24,
            pty_writers: Arc::new(Mutex::new(HashMap::new())),
            pty_children: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub struct SshSession {
    db: Arc<Db>,
    shell_config: Arc<ShellConfig>,
    domain: String,
    web_port: u16,
    user_id: Option<String>,
    token: Option<String>,
    cols: u16,
    rows: u16,
    pty_writers: Arc<Mutex<HashMap<ChannelId, pty_process::OwnedWritePty>>>,
    pty_children: Arc<Mutex<HashMap<ChannelId, tokio::process::Child>>>,
}

fn ki_only() -> Option<MethodSet> {
    Some(MethodSet::from(&[MethodKind::KeyboardInteractive][..]))
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    fn auth_none(&mut self, _user: &str) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async {
            Ok(Auth::Reject {
                proceed_with_methods: ki_only(),
                partial_success: false,
            })
        }
    }

    fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<russh::server::Response<'a>>,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async move {
            if response.is_none() {
                let token = hex::encode(rand::random::<[u8; 3]>());
                self.db.create_session(&token)?;
                self.token = Some(token.clone());

                let url = if self.domain == "localhost" || self.domain == "127.0.0.1" {
                    format!("http://{}:{}/auth/{}", self.domain, self.web_port, token)
                } else {
                    format!("https://{}/auth/{}", self.domain, token)
                };
                let instruction = format!(
                    "{}\n  Authenticate with your passkey:\n\n  {}\n\n  Waiting...\n",
                    CAT_ART, url
                );

                return Ok(Auth::Partial {
                    name: Cow::Borrowed(""),
                    instructions: Cow::Owned(instruction),
                    prompts: Cow::Borrowed(&[]),
                });
            }

            let token = match &self.token {
                Some(t) => t.clone(),
                None => {
                    return Ok(Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    })
                }
            };

            let start = tokio::time::Instant::now();
            loop {
                if let Some(session) = self.db.get_session(&token) {
                    if session.status == "approved" {
                        self.user_id = session.user_id.clone();
                        tracing::info!("SSH: User {:?} authenticated", self.user_id);
                        return Ok(Auth::Accept);
                    }
                }

                if start.elapsed() > std::time::Duration::from_secs(120) {
                    return Ok(Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    });
                }

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }

    fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async {
            Ok(Auth::Reject {
                proceed_with_methods: ki_only(),
                partial_success: false,
            })
        }
    }

    fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }

    fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        self.cols = col_width as u16;
        self.rows = row_height as u16;
        session.channel_success(channel).ok();
        async { Ok(()) }
    }

    fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        self.cols = col_width as u16;
        self.rows = row_height as u16;
        let pty_writers = self.pty_writers.clone();
        async move {
            let writers = pty_writers.lock().await;
            if let Some(writer) = writers.get(&channel) {
                writer.resize(pty_process::Size::new(row_height as u16, col_width as u16)).ok();
            }
            Ok(())
        }
    }

    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let shell_config = self.shell_config.clone();
        let cols = self.cols;
        let rows = self.rows;
        let handle = session.handle();
        let pty_writers = self.pty_writers.clone();
        let pty_children = self.pty_children.clone();
        let user_id = self.user_id.clone();

        session.channel_success(channel).ok();

        async move {
            if user_id.is_none() {
                handle.close(channel).await.ok();
                return Ok(());
            }

            let (pty, child) = match pty::spawn_pty(&shell_config, cols, rows) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to spawn PTY: {:?}", e);
                    let msg = format!("\r\nError starting shell: {}\r\n", e);
                    handle.data(channel, CryptoVec::from(msg.as_bytes())).await.ok();
                    handle.close(channel).await.ok();
                    return Ok(());
                }
            };

            let (mut pty_reader, pty_writer) = pty.into_split();
            pty_writers.lock().await.insert(channel, pty_writer);
            pty_children.lock().await.insert(channel, child);

            // PTY output → SSH channel
            let h = handle.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match pty_reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if h.data(channel, CryptoVec::from_slice(&buf[..n])).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                h.eof(channel).await.ok();
                h.close(channel).await.ok();
            });

            tracing::info!("SSH: Shell started for user {:?}", user_id);
            Ok(())
        }
    }

    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let pty_writers = self.pty_writers.clone();
        let data = data.to_vec();
        async move {
            let mut writers = pty_writers.lock().await;
            if let Some(writer) = writers.get_mut(&channel) {
                if writer.write_all(&data).await.is_err() {
                    writers.remove(&channel);
                }
            }
            Ok(())
        }
    }

    fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let pty_writers = self.pty_writers.clone();
        let pty_children = self.pty_children.clone();
        async move {
            pty_writers.lock().await.remove(&channel);
            if let Some(mut child) = pty_children.lock().await.remove(&channel) {
                child.kill().await.ok();
            }
            Ok(())
        }
    }
}

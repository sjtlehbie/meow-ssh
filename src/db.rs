use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub user_id: Option<String>,
    pub status: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub id: String,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub transports: Option<String>,
    pub device_type: Option<String>,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=1;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ssh_sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                expires_at INTEGER NOT NULL,
                created_at INTEGER DEFAULT (unixepoch())
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                counter INTEGER NOT NULL DEFAULT 0,
                transports TEXT,
                device_type TEXT,
                created_at INTEGER DEFAULT (unixepoch())
            );
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // --- SSH Sessions ---

    pub fn create_session(&self, token: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let expires_at = now() + 300;
        conn.execute(
            "INSERT INTO ssh_sessions (token, status, expires_at) VALUES (?1, 'pending', ?2)",
            rusqlite::params![token, expires_at],
        )?;
        Ok(())
    }

    pub fn get_session(&self, token: &str) -> Option<Session> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT token, user_id, status, expires_at FROM ssh_sessions WHERE token = ?1 AND expires_at > ?2",
            rusqlite::params![token, now()],
            |row| {
                Ok(Session {
                    token: row.get(0)?,
                    user_id: row.get(1)?,
                    status: row.get(2)?,
                    expires_at: row.get(3)?,
                })
            },
        )
        .ok()
    }

    pub fn approve_session(&self, token: &str, user_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE ssh_sessions SET status = 'approved', user_id = ?1 WHERE token = ?2 AND status = 'pending'",
            rusqlite::params![user_id, token],
        )?;
        Ok(())
    }

    pub fn create_terminal_token(&self, token: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let expires_at = now() + 300;
        conn.execute(
            "INSERT OR REPLACE INTO ssh_sessions (token, user_id, status, expires_at) VALUES (?1, 'local', 'terminal', ?2)",
            rusqlite::params![token, expires_at],
        )?;
        Ok(())
    }

    pub fn consume_terminal_token(&self, token: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        let user_id: Option<String> = conn
            .query_row(
                "SELECT user_id FROM ssh_sessions WHERE token = ?1 AND status = 'terminal' AND expires_at > ?2",
                rusqlite::params![token, now()],
                |row| row.get(0),
            )
            .ok()?;
        conn.execute(
            "DELETE FROM ssh_sessions WHERE token = ?1",
            rusqlite::params![token],
        )
        .ok();
        user_id
    }

    // --- WebAuthn Credentials ---

    pub fn store_credential(
        &self,
        id: &str,
        public_key: &[u8],
        counter: u32,
        transports: Option<&str>,
        device_type: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO credentials (id, public_key, counter, transports, device_type) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![id, public_key, counter, transports, device_type],
        )?;
        Ok(())
    }

    pub fn get_credential(&self, id: &str) -> Option<StoredCredential> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, public_key, counter, transports, device_type FROM credentials WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(StoredCredential {
                    id: row.get(0)?,
                    public_key: row.get(1)?,
                    counter: row.get(2)?,
                    transports: row.get(3)?,
                    device_type: row.get(4)?,
                })
            },
        )
        .ok()
    }

    pub fn get_all_credentials(&self) -> Vec<StoredCredential> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT id, public_key, counter, transports, device_type FROM credentials")
            .unwrap();
        stmt.query_map([], |row| {
            Ok(StoredCredential {
                id: row.get(0)?,
                public_key: row.get(1)?,
                counter: row.get(2)?,
                transports: row.get(3)?,
                device_type: row.get(4)?,
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    pub fn update_counter(&self, id: &str, new_counter: u32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE credentials SET counter = ?1 WHERE id = ?2",
            rusqlite::params![new_counter, id],
        )?;
        Ok(())
    }

    pub fn update_credential_blob(&self, id: &str, blob: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE credentials SET public_key = ?1 WHERE id = ?2",
            rusqlite::params![blob, id],
        )?;
        Ok(())
    }

    pub fn has_credentials(&self) -> bool {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
            .unwrap_or(0);
        count > 0
    }

    // --- Config (challenges, etc.) ---

    pub fn set_config(&self, key: &str, value: &str, expires_at: Option<i64>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value, expires_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![key, value, expires_at],
        )?;
        Ok(())
    }

    pub fn get_config(&self, key: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM config WHERE key = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
            rusqlite::params![key, now()],
            |row| row.get(0),
        )
        .ok()
    }

    pub fn delete_config(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM config WHERE key = ?1", rusqlite::params![key])?;
        Ok(())
    }

    // --- Cleanup ---

    pub fn cleanup_expired(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM ssh_sessions WHERE expires_at < ?1",
            rusqlite::params![now()],
        )?;
        conn.execute(
            "DELETE FROM config WHERE expires_at IS NOT NULL AND expires_at < ?1",
            rusqlite::params![now()],
        )?;
        Ok(())
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

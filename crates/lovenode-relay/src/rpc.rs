//! Minimal JSON-RPC client for a Divi node (`divid`).
//!
//! Deliberately blocking and dependency-light. The relay talks to a node it
//! runs itself, over loopback or an SSH tunnel — never to an untrusted node.

use serde_json::{json, Value};

#[derive(Clone)]
pub struct NodeRpc {
    url: String,
    user: String,
    pass: String,
    timeout_secs: u64,
}

// Hand-written so the RPC password can never reach a log through a debug format,
// the same care StakingKey takes with key material.
impl std::fmt::Debug for NodeRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRpc").field("url", &self.url).field("pass", &"<redacted>").finish()
    }
}

impl NodeRpc {
    pub fn new(host: &str, port: u16, user: &str, pass: &str) -> Self {
        Self {
            url: format!("http://{host}:{port}"),
            user: user.to_string(),
            pass: pass.to_string(),
            timeout_secs: 15,
        }
    }

    /// Read a node's credentials from a `divi.conf`, the same way the desktop
    /// wallet does. Keeps secrets out of this repo and out of process args.
    pub fn from_conf(conf_text: &str, host: &str) -> Result<Self, String> {
        let mut user = String::new();
        let mut pass = String::new();
        let mut port = 51473u16;
        for line in conf_text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "rpcuser" => user = v.trim().to_string(),
                    "rpcpassword" => pass = v.trim().to_string(),
                    "rpcport" => port = v.trim().parse().unwrap_or(port),
                    _ => {}
                }
            }
        }
        if user.is_empty() || pass.is_empty() {
            return Err("divi.conf has no rpcuser/rpcpassword".into());
        }
        Ok(Self::new(host, port, &user, &pass))
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "1.0", "id": "lovenode", "method": method, "params": params });
        let resp = ureq::post(&self.url)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .set(
                "Authorization",
                &format!(
                    "Basic {}",
                    base64_encode(format!("{}:{}", self.user, self.pass).as_bytes())
                ),
            )
            .send_json(body);

        let value: Value = match resp {
            Ok(r) => r.into_json().map_err(|e| format!("bad JSON from node: {e}"))?,
            Err(ureq::Error::Status(_, r)) => {
                // The node returns useful errors in the body even on 500.
                r.into_json().map_err(|e| format!("node error, unreadable body: {e}"))?
            }
            Err(e) => return Err(format!("cannot reach the Divi node: {e}")),
        };

        if let Some(err) = value.get("error") {
            if !err.is_null() {
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown node error");
                return Err(format!("{method}: {msg}"));
            }
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: node returned no result"))
    }
}

/// Small base64 encoder so the relay needs no extra dependency for HTTP auth.
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn conf_parsing_picks_up_credentials_and_port() {
        let conf = "# comment\nrpcuser = alice \nrpcpassword=s3cret\nrpcport= 51799\nlisten=0\n";
        let rpc = NodeRpc::from_conf(conf, "127.0.0.1").unwrap();
        assert_eq!(rpc.user, "alice");
        assert_eq!(rpc.pass, "s3cret");
        assert_eq!(rpc.url, "http://127.0.0.1:51799");
    }

    #[test]
    fn conf_without_credentials_is_rejected() {
        assert!(NodeRpc::from_conf("listen=0\n", "127.0.0.1").is_err());
    }
}

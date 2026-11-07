use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use super::{AddrMaybeCached, SocketOpts, TcpTransport, Transport, TransportRole};
use crate::config::{NoiseConfig, TransportConfig};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use snowstorm::snow::params::DHChoice;
use snowstorm::{Builder, NoiseParams, NoiseStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// How the pattern's initiator (the rathole client) presents its static key,
/// from the first letter of the pattern name (`Noise_KK_...` -> `K`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitiatorStatic {
    /// `N`: the client has no static key, so the server can't authenticate it
    None,
    /// `K`: the server must know the client key before the first message
    Known,
    /// `X` or `I`: the client sends its key during the handshake
    Transmitted,
}

impl InitiatorStatic {
    fn from_pattern(pattern: &str) -> Result<InitiatorStatic> {
        let name = pattern
            .split('_')
            .nth(1)
            .ok_or_else(|| anyhow!("Malformed noise pattern {}", pattern))?;
        match name.chars().next() {
            Some('N') => Ok(InitiatorStatic::None),
            Some('K') => Ok(InitiatorStatic::Known),
            Some('X') | Some('I') => Ok(InitiatorStatic::Transmitted),
            _ => bail!("Unsupported noise handshake pattern {}", name),
        }
    }
}

pub struct NoiseTransport {
    tcp: TcpTransport,
    config: NoiseConfig,
    params: NoiseParams,
    local_private_key: Vec<u8>,
    /// Client: the server's key (at most one). Server: the allowed client keys.
    remote_public_keys: Vec<Vec<u8>>,
    initiator_static: InitiatorStatic,
}

impl std::fmt::Debug for NoiseTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self.config)
    }
}

impl NoiseTransport {
    fn builder<'a>(&'a self, remote_public_key: Option<&'a [u8]>) -> Builder<'a> {
        let builder = Builder::new(self.params.clone()).local_private_key(&self.local_private_key);
        match remote_public_key {
            Some(x) => builder.remote_public_key(x),
            None => builder,
        }
    }

    /// KK and other `K` patterns with several allowed client keys: the server
    /// needs the client key before it can read the first message, so try each
    /// one. Only the right key authenticates the message (its `ss` term keys
    /// the payload's AEAD tag). Then replay the message into a normal handshake.
    async fn handshake_known_client(
        &self,
        mut conn: TcpStream,
    ) -> Result<NoiseStream<PrefixedStream>> {
        let len = conn.read_u16_le().await? as usize;
        let mut msg = vec![0u8; len];
        conn.read_exact(&mut msg).await?;

        let mut payload = vec![0u8; len];
        let key = self
            .remote_public_keys
            .iter()
            .find(|k| {
                self.builder(Some(k))
                    .build_responder()
                    .map(|mut state| state.read_message(&msg, &mut payload).is_ok())
                    .unwrap_or(false)
            })
            .ok_or_else(|| anyhow!("Noise handshake from a client key that isn't allowed"))?;

        let mut prefix = Vec::with_capacity(2 + len);
        prefix.extend_from_slice(&(len as u16).to_le_bytes());
        prefix.extend_from_slice(&msg);
        Ok(NoiseStream::handshake(
            PrefixedStream::with_prefix(conn, prefix),
            self.builder(Some(key)).build_responder()?,
        )
        .await?)
    }
}

#[async_trait]
impl Transport for NoiseTransport {
    type Acceptor = TcpListener;
    type RawStream = TcpStream;
    type Stream = snowstorm::stream::NoiseStream<PrefixedStream>;

    fn new(config: &TransportConfig, role: TransportRole) -> Result<Self> {
        let tcp = TcpTransport::new(config, role)?;

        let config = match &config.noise {
            Some(v) => v.clone(),
            None => return Err(anyhow!("Missing noise config")),
        };
        let builder = Builder::new(config.pattern.parse()?);
        let params: NoiseParams = config.pattern.parse()?;
        let key_len = match params.dh {
            DHChoice::Curve25519 => 32,
            DHChoice::Ed448 => 56,
        };
        let initiator_static = InitiatorStatic::from_pattern(&config.pattern)?;

        let mut remote_public_keys: Vec<Vec<u8>> = Vec::new();
        for (i, x) in config
            .remote_public_key
            .iter()
            .chain(config.remote_public_keys.iter().flatten())
            .enumerate()
        {
            let key = base64::decode(x)
                .with_context(|| format!("Failed to decode remote public key #{}", i + 1))?;
            if key.len() != key_len {
                bail!(
                    "Remote public key #{} is {} bytes, but {} needs {}",
                    i + 1,
                    key.len(),
                    config.pattern,
                    key_len
                );
            }
            if !remote_public_keys.contains(&key) {
                remote_public_keys.push(key);
            }
        }
        match role {
            TransportRole::Client if config.remote_public_keys.is_some() => {
                bail!("`remote_public_keys` is for servers; a client takes the server's key in `remote_public_key`")
            }
            TransportRole::Server
                if initiator_static == InitiatorStatic::None
                    && config.remote_public_keys.is_some() =>
            {
                bail!(
                    "Pattern {} doesn't authenticate clients, so `remote_public_keys` would have no effect",
                    config.pattern
                )
            }
            TransportRole::Server
                if initiator_static == InitiatorStatic::Known && remote_public_keys.is_empty() =>
            {
                bail!(
                    "Pattern {} needs the client public key in `remote_public_key` or `remote_public_keys`",
                    config.pattern
                )
            }
            _ => {}
        }

        let local_private_key = match &config.local_private_key {
            Some(x) => base64::decode(x.as_bytes())
                .with_context(|| "Failed to decode local_private_key")?,
            None => builder.generate_keypair()?.private,
        };
        if local_private_key.len() != key_len {
            bail!(
                "local_private_key is {} bytes, but {} needs {}",
                local_private_key.len(),
                config.pattern,
                key_len
            );
        }

        Ok(NoiseTransport {
            tcp,
            config,
            params,
            local_private_key,
            remote_public_keys,
            initiator_static,
        })
    }

    fn hint(conn: &Self::Stream, opt: SocketOpts) {
        opt.apply(conn.get_inner().get_ref());
    }

    async fn bind<T: ToSocketAddrs + Send + Sync>(&self, addr: T) -> Result<Self::Acceptor> {
        Ok(TcpListener::bind(addr).await?)
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        self.tcp
            .accept(a)
            .await
            .with_context(|| "Failed to accept TCP connection")
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        let keys = &self.remote_public_keys;
        let conn = match self.initiator_static {
            InitiatorStatic::Known if keys.len() > 1 => self.handshake_known_client(conn).await,
            // The client sends its key: check it against the allowed ones
            InitiatorStatic::Transmitted if !keys.is_empty() => {
                NoiseStream::handshake_with_verifier(
                    PrefixedStream::new(conn),
                    self.builder(None).build_responder()?,
                    |k| {
                        if keys.iter().any(|x| x.as_slice() == k) {
                            Ok(())
                        } else {
                            Err(snowstorm::SnowstormError::HandshakeError(
                                "client key isn't allowed".into(),
                            ))
                        }
                    },
                )
                .await
                .map_err(Into::into)
            }
            InitiatorStatic::Known => NoiseStream::handshake(
                PrefixedStream::new(conn),
                self.builder(keys.first().map(Vec::as_slice))
                    .build_responder()?,
            )
            .await
            .map_err(Into::into),
            _ => NoiseStream::handshake(
                PrefixedStream::new(conn),
                self.builder(None).build_responder()?,
            )
            .await
            .map_err(Into::into),
        };
        conn.with_context(|| "Failed to do noise handshake")
    }

    async fn connect(&self, addr: &AddrMaybeCached) -> Result<Self::Stream> {
        let conn = self
            .tcp
            .connect(addr)
            .await
            .with_context(|| "Failed to connect TCP socket")?;

        let conn = NoiseStream::handshake(
            PrefixedStream::new(conn),
            self.builder(self.remote_public_keys.first().map(Vec::as_slice))
                .build_initiator()?,
        )
        .await
        .with_context(|| "Failed to do noise handshake")?;
        return Ok(conn);
    }
}

/// A TCP stream that first yields bytes already read from it, so a handshake
/// message inspected by the server can be fed to the real handshake
#[derive(Debug)]
pub struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(inner: TcpStream) -> PrefixedStream {
        Self::with_prefix(inner, Vec::new())
    }

    fn with_prefix(inner: TcpStream, prefix: Vec<u8>) -> PrefixedStream {
        PrefixedStream {
            prefix,
            pos: 0,
            inner,
        }
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.inner
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = buf.remaining().min(this.prefix.len() - this.pos);
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportType;
    use tokio::io::AsyncWriteExt;

    fn keypair() -> (String, String) {
        let kp = Builder::new("Noise_KK_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .generate_keypair()
            .unwrap();
        (base64::encode(kp.private), base64::encode(kp.public))
    }

    fn transport(
        role: TransportRole,
        pattern: &str,
        private: &str,
        remote: Option<&str>,
        more: Option<Vec<String>>,
    ) -> Result<NoiseTransport> {
        NoiseTransport::new(
            &TransportConfig {
                transport_type: TransportType::Noise,
                noise: Some(NoiseConfig {
                    pattern: pattern.into(),
                    local_private_key: Some(private.into()),
                    remote_public_key: remote.map(String::from),
                    remote_public_keys: more,
                }),
                ..Default::default()
            },
            role,
        )
    }

    /// Handshake `client` against `server` over a real socket and echo a byte
    async fn connects(server: &NoiseTransport, client: &NoiseTransport) -> bool {
        let listener = server.bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let mut target = AddrMaybeCached::new(&addr);
        target.resolve().await.unwrap();
        let client_side = async {
            let mut c = client.connect(&target).await?;
            c.write_all(b"x").await?;
            c.flush().await?;
            let mut b = [0u8; 1];
            c.read_exact(&mut b).await?;
            anyhow::Ok(b)
        };
        let server_side = async {
            let (raw, _) = server.accept(&listener).await?;
            let mut s = server.handshake(raw).await?;
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await?;
            s.write_all(&b).await?;
            s.flush().await?;
            anyhow::Ok(())
        };
        let (c, s) = tokio::join!(client_side, server_side);
        matches!((c, s), (Ok(b), Ok(())) if &b == b"x")
    }

    const KK: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
    const IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

    #[tokio::test]
    async fn kk_accepts_each_listed_client_key_and_rejects_others() {
        let (srv_priv, srv_pub) = keypair();
        let clients: Vec<_> = (0..3).map(|_| keypair()).collect();
        let (stranger_priv, _) = keypair();
        let server = transport(
            TransportRole::Server,
            KK,
            &srv_priv,
            Some(&clients[0].1),
            Some(clients[1..].iter().map(|c| c.1.clone()).collect()),
        )
        .unwrap();
        for (private, _) in &clients {
            let client =
                transport(TransportRole::Client, KK, private, Some(&srv_pub), None).unwrap();
            assert!(connects(&server, &client).await);
        }
        let stranger = transport(
            TransportRole::Client,
            KK,
            &stranger_priv,
            Some(&srv_pub),
            None,
        )
        .unwrap();
        assert!(!connects(&server, &stranger).await);
    }

    #[tokio::test]
    async fn kk_single_key_still_works() {
        let (srv_priv, srv_pub) = keypair();
        let (cli_priv, cli_pub) = keypair();
        let server = transport(TransportRole::Server, KK, &srv_priv, Some(&cli_pub), None).unwrap();
        let client = transport(TransportRole::Client, KK, &cli_priv, Some(&srv_pub), None).unwrap();
        assert!(connects(&server, &client).await);
    }

    #[tokio::test]
    async fn ik_checks_transmitted_client_key() {
        let (srv_priv, srv_pub) = keypair();
        let (a_priv, a_pub) = keypair();
        let (b_priv, _) = keypair();
        let server = transport(
            TransportRole::Server,
            IK,
            &srv_priv,
            None,
            Some(vec![a_pub]),
        )
        .unwrap();
        let a = transport(TransportRole::Client, IK, &a_priv, Some(&srv_pub), None).unwrap();
        let b = transport(TransportRole::Client, IK, &b_priv, Some(&srv_pub), None).unwrap();
        assert!(connects(&server, &a).await);
        assert!(!connects(&server, &b).await);
    }

    #[test]
    fn rejects_misplaced_or_useless_key_lists() {
        let (k, p) = keypair();
        let nk = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
        assert!(transport(
            TransportRole::Client,
            KK,
            &k,
            Some(&p),
            Some(vec![p.clone()])
        )
        .is_err());
        assert!(transport(TransportRole::Server, nk, &k, None, Some(vec![p.clone()])).is_err());
        assert!(transport(TransportRole::Server, KK, &k, None, None).is_err());
        assert!(transport(TransportRole::Server, KK, &k, Some("not base64!"), None).is_err());
        // empty or truncated keys fail at startup, not on every handshake
        assert!(transport(TransportRole::Server, KK, &k, Some(""), None).is_err());
        assert!(transport(
            TransportRole::Server,
            KK,
            &k,
            Some(&p),
            Some(vec!["AAAA".into()])
        )
        .is_err());
        assert!(transport(TransportRole::Server, KK, "", Some(&p), None).is_err());
    }
}

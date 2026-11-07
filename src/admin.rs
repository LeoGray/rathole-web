use crate::auth_throttle::{AuthThrottle, Failure, SourceKey};
use crate::helper::{constant_time_eq, log_ip};
use crate::{config::AdminConfig, Config, RunMode};
use anyhow::{anyhow, bail, Context, Result};
use hyper::body::HttpBody;
use hyper::header::HeaderValue;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use lazy_static::lazy_static;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Value shown in place of each secret by `GET /api/config`. A `PUT` that
/// still contains it keeps the secret currently on disk.
const REDACTED: &str = "<redacted>";
/// Keys whose values are secrets anywhere in the config
const SECRET_KEYS: &[&str] = &[
    "token",
    "default_token",
    "local_private_key",
    "pkcs12_password",
];
/// Largest config accepted by `PUT /api/config`
const MAX_CONFIG_BYTES: usize = 1 << 20;
/// Failed admin logins from one source before it is refused for `ADMIN_BAN`
const ADMIN_FAIL_LIMIT: u32 = 5;
const ADMIN_FAIL_WINDOW: Duration = Duration::from_secs(60);
const ADMIN_BAN: Duration = Duration::from_secs(300);
/// The page has inline script and style but loads nothing from elsewhere and
/// may only talk to this origin, so injected markup can't exfiltrate the token
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
                   connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; \
                   frame-ancestors 'none'";

pub struct AdminContext {
    pub mode: RunMode,
    pub bind_addr: String,
    pub token: String,
    pub config_path: PathBuf,
    /// Live control channels per service. A count rather than a flag, because a
    /// replaced channel reports its shutdown after its successor connected.
    pub status: Arc<RwLock<HashMap<String, u32>>>,
    throttle: AuthThrottle,
}

lazy_static! {
    static ref ADMIN_CONTEXT: RwLock<Option<Arc<AdminContext>>> = RwLock::new(None);
}

#[derive(Serialize)]
struct ServiceStatus {
    name: String,
    connected: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    mode: &'static str,
    services: Vec<ServiceStatus>,
}

const HTML_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>rathole admin</title>
  <style>
    :root {
      --bg: #0b0f10;
      --panel: #0f1417;
      --border: #1f2a2f;
      --text: #9dfc98;
      --muted: #6aa46c;
      --accent: #53e37a;
      --error: #ff6b6b;
      --scan: rgba(255,255,255,0.02);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 18px;
      background: var(--bg);
      color: var(--text);
      font-family: "IBM Plex Mono", Menlo, Consolas, monospace;
      line-height: 1.5;
      position: relative;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      background: linear-gradient(rgba(255,255,255,0.03), rgba(255,255,255,0.01));
      mix-blend-mode: screen;
      opacity: 0.5;
    }
    h2 {
      margin: 0 0 8px;
      font-size: 18px;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      padding: 14px;
      margin-bottom: 14px;
      box-shadow: 0 0 0 1px rgba(0,0,0,0.4);
    }
    .panel + .panel { margin-top: 0; }
    .bar {
      padding: 6px 10px;
      background: #0c1215;
      border: 1px solid var(--border);
      margin: 8px 0;
      color: var(--muted);
      font-size: 13px;
    }
    textarea, input {
      width: 100%;
      background: #0a0f12;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px;
      font-family: "IBM Plex Mono", Menlo, Consolas, monospace;
      font-size: 13px;
      outline: none;
    }
    textarea { min-height: 220px; }
    input { max-width: 320px; }
    .actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 8px; }
    button {
      background: transparent;
      color: var(--accent);
      border: 1px solid var(--accent);
      padding: 8px 12px;
      font-family: inherit;
      font-size: 13px;
      cursor: pointer;
      transition: background 0.2s, color 0.2s;
    }
    button:hover { background: var(--accent); color: #0b0f10; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td {
      padding: 6px 4px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      font-size: 13px;
    }
    th { color: var(--muted); font-weight: 600; }
    .status-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      border: 1px solid var(--border);
      background: #0a0f12;
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }
    .ok { color: var(--accent); }
    .ok .dot { background: var(--accent); box-shadow: 0 0 6px var(--accent); }
    .bad { color: var(--error); }
    .bad .dot { background: var(--error); box-shadow: 0 0 6px var(--error); }
    #message { font-size: 12px; color: var(--muted); min-height: 16px; }
  </style>
</head>
<body>
  <div class="panel">
    <div class="actions">
      <h2 id="token-title">管理令牌</h2>
      <button id="lang-toggle" onclick="toggleLang()" style="margin-left:auto;">EN</button>
    </div>
    <div class="actions">
      <input id="token" type="password" placeholder="Bearer token" />
      <button id="save-token-btn" onclick="saveToken()">保存</button>
      <span id="message"></span>
    </div>
  </div>
  <div class="panel">
    <h2 id="status-title">服务状态</h2>
    <div class="bar" id="mode"></div>
    <table>
      <thead><tr><th id="service-name-th">服务名</th><th id="status-th">状态</th></tr></thead>
      <tbody id="status-body"></tbody>
    </table>
  </div>
  <div class="panel">
    <h2 id="config-title">配置</h2>
    <textarea id="config"></textarea>
    <div class="actions">
      <button id="refresh-btn" onclick="loadConfig()">刷新配置</button>
      <button id="save-config-btn" onclick="saveConfig()">保存并热重载</button>
    </div>
  </div>
  <script>
    const translations = {
      en: {
        tokenTitle: 'Admin Token',
        saveToken: 'Save',
        tokenSaved: 'Token saved',
        statusTitle: 'Service Status',
        modeLabel: 'Mode',
        serviceName: 'Service',
        status: 'Status',
        connected: 'Connected',
        disconnected: 'Disconnected',
        loadStatusFailed: 'Failed to load status: ',
        configTitle: 'Config',
        refreshConfig: 'Refresh config',
        saveConfig: 'Save & hot-reload',
        configLoaded: 'Config loaded',
        saving: 'Saved, hot reloading',
        loadConfigFailed: 'Failed to load config: ',
        saveConfigFailed: 'Save failed: ',
        tokenPlaceholder: 'Admin token',
        langAlt: '中文'
      },
      zh: {
        tokenTitle: '管理令牌',
        saveToken: '保存',
        tokenSaved: 'Token 已保存',
        statusTitle: '服务状态',
        modeLabel: '运行模式',
        serviceName: '服务名',
        status: '状态',
        connected: '已连接',
        disconnected: '未连接',
        loadStatusFailed: '加载状态失败: ',
        configTitle: '配置',
        refreshConfig: '刷新配置',
        saveConfig: '保存并热重载',
        configLoaded: '配置已加载',
        saving: '已保存，热重载中',
        loadConfigFailed: '加载配置失败: ',
        saveConfigFailed: '保存失败: ',
        tokenPlaceholder: '管理 token',
        langAlt: 'EN'
      }
    };

    let lang = (() => {
      const stored = localStorage.getItem('rathole_admin_lang');
      if (stored && translations[stored]) return stored;
      return navigator.language && navigator.language.startsWith('zh') ? 'zh' : 'en';
    })();

    const tokenInput = document.getElementById('token');
    const statusBody = document.getElementById('status-body');
    const modeSpan = document.getElementById('mode');
    const cfg = document.getElementById('config');
    const msg = document.getElementById('message');

    function t(key) { return (translations[lang] && translations[lang][key]) || translations.en[key] || key; }

    function applyLang() {
      document.documentElement.lang = lang;
      document.getElementById('token-title').textContent = t('tokenTitle');
      document.getElementById('save-token-btn').textContent = t('saveToken');
      document.getElementById('status-title').textContent = t('statusTitle');
      document.getElementById('service-name-th').textContent = t('serviceName');
      document.getElementById('status-th').textContent = t('status');
      document.getElementById('config-title').textContent = t('configTitle');
      document.getElementById('refresh-btn').textContent = t('refreshConfig');
      document.getElementById('save-config-btn').textContent = t('saveConfig');
      document.getElementById('lang-toggle').textContent = t('langAlt');
      tokenInput.placeholder = t('tokenPlaceholder');
      const saveLabel = t('saveToken');
      document.getElementById('save-token-btn').textContent = saveLabel;
    }

    function toggleLang() {
      lang = lang === 'en' ? 'zh' : 'en';
      localStorage.setItem('rathole_admin_lang', lang);
      applyLang();
      loadStatus();
      loadConfig();
    }

    // sessionStorage: the token is gone when the tab closes instead of staying on disk
    try { localStorage.removeItem('rathole_admin_token'); } catch (e) {}
    function getToken() { try { return sessionStorage.getItem('rathole_admin_token') || ''; } catch (e) { return ''; } }
    function saveToken() { try { sessionStorage.setItem('rathole_admin_token', tokenInput.value); } catch (e) {} msg.textContent = t('tokenSaved'); setTimeout(()=>msg.textContent='',1500); }
    tokenInput.value = getToken();
    applyLang();

    async function api(path, options={}) {
      const headers = options.headers || {};
      const token = getToken();
      if (token) headers['Authorization'] = 'Bearer ' + token;
      const res = await fetch(path, { ...options, headers });
      if (!res.ok) throw new Error(await res.text() || res.statusText);
      return res;
    }

    function esc(s) {
      return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    async function loadStatus() {
      try {
        const res = await api('/api/status');
        const data = await res.json();
        modeSpan.textContent = t('modeLabel') + ': ' + data.mode;
        statusBody.innerHTML = data.services.map(s => {
          const cls = s.connected ? 'ok' : 'bad';
          const text = s.connected ? t('connected') : t('disconnected');
          return `<tr><td>${esc(s.name)}</td><td><span class="status-chip ${cls}"><span class="dot"></span>${text}</span></td></tr>`;
        }).join('');
      } catch (e) { msg.textContent = t('loadStatusFailed') + e.message; }
    }

    async function loadConfig() {
      try {
        const res = await api('/api/config');
        cfg.value = await res.text();
        msg.textContent = t('configLoaded');
        setTimeout(()=>msg.textContent='',1500);
      } catch (e) { msg.textContent = t('loadConfigFailed') + e.message; }
    }

    async function saveConfig() {
      try {
        await api('/api/config', { method: 'PUT', body: cfg.value });
        msg.textContent = t('saving');
        setTimeout(()=>msg.textContent='',1500);
      } catch (e) { msg.textContent = t('saveConfigFailed') + e.message; }
    }

    loadStatus();
    loadConfig();
    setInterval(loadStatus, 3000);
  </script>
</body>
</html>
"#;

pub async fn init_admin(
    config_path: PathBuf,
    admin_cfg: AdminConfig,
    mode: RunMode,
    services: Vec<String>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<bool>,
) -> Result<()> {
    let ctx = Arc::new(AdminContext {
        mode,
        bind_addr: admin_cfg.bind_addr,
        token: admin_cfg.token.to_string(),
        config_path,
        status: Arc::new(RwLock::new(HashMap::new())),
        throttle: AuthThrottle::new(ADMIN_FAIL_LIMIT, ADMIN_FAIL_WINDOW, ADMIN_BAN),
    });

    {
        let mut guard = ADMIN_CONTEXT.write().await;
        *guard = Some(ctx.clone());
    }

    {
        let mut status = ctx.status.write().await;
        for name in services {
            status.insert(name, 0);
        }
    }

    let bind_addr: SocketAddr = ctx.bind_addr.parse().context("Invalid admin bind_addr")?;
    if !bind_addr.ip().is_loopback() {
        warn!(
            "Admin UI on non-loopback address {} is plain HTTP: the admin token and config secrets \
             cross the network unencrypted. Prefer 127.0.0.1 with an SSH tunnel or a TLS proxy",
            bind_addr
        );
    }
    // try_bind: Server::bind panics on failure, which aborts the whole process
    let builder = Server::try_bind(&bind_addr)
        .with_context(|| format!("Failed to bind the admin UI to {}", bind_addr))?;
    let server_ctx = ctx.clone();

    tokio::spawn(async move {
        info!("Admin UI listening at {}", server_ctx.bind_addr);
        let make_svc = make_service_fn(move |conn: &AddrStream| {
            let ctx = server_ctx.clone();
            let peer = conn.remote_addr();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let ctx = ctx.clone();
                    async move {
                        match handle(req, peer, ctx.clone()).await {
                            Ok(resp) => Ok::<_, hyper::Error>(with_security_headers(resp)),
                            Err(err) => {
                                error!("{:#}", err);
                                Ok::<_, hyper::Error>(with_security_headers(
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("internal error"))
                                        .unwrap(),
                                ))
                            }
                        }
                    }
                }))
            }
        });

        let server = builder.serve(make_svc);

        let graceful = server.with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
        });

        if let Err(e) = graceful.await {
            error!("Admin server error: {:#}", e);
        }
    });

    Ok(())
}

pub async fn add_service(name: &str) {
    if let Some(ctx) = current_context().await {
        let mut status = ctx.status.write().await;
        status.entry(name.to_string()).or_insert(0);
    }
}

pub async fn remove_service(name: &str) {
    if let Some(ctx) = current_context().await {
        let mut status = ctx.status.write().await;
        status.remove(name);
    }
}

pub async fn set_service_status(name: &str, connected: bool) {
    if let Some(ctx) = current_context().await {
        let mut status = ctx.status.write().await;
        let live = status.entry(name.to_string()).or_insert(0);
        *live = if connected {
            live.saturating_add(1)
        } else {
            live.saturating_sub(1)
        };
    }
}

async fn current_context() -> Option<Arc<AdminContext>> {
    ADMIN_CONTEXT.read().await.clone()
}

async fn handle(
    req: Request<Body>,
    peer: SocketAddr,
    ctx: Arc<AdminContext>,
) -> Result<Response<Body>> {
    if req.method() == Method::GET && req.uri().path() == "/" {
        return Ok(Response::builder()
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(HTML_PAGE))
            .unwrap());
    }

    if ctx.throttle.is_blocked(peer.ip()) {
        return Ok(Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("retry-after", ADMIN_BAN.as_secs().to_string())
            .body(Body::from("too many failed attempts"))
            .unwrap());
    }

    if !authorized(&req, &ctx.token) {
        match ctx.throttle.record_failure(peer.ip()) {
            Failure::Banned => warn!(
                peer = %log_ip(peer),
                "Admin UI: refusing {} for {}s after repeated bad tokens",
                log_ip(SourceKey::from_ip(peer.ip())),
                ADMIN_BAN.as_secs()
            ),
            Failure::Counted(_) | Failure::AlreadyBanned => {}
        }
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("www-authenticate", "Bearer")
            .body(Body::from("unauthorized"))
            .unwrap());
    }
    ctx.throttle.record_success(peer.ip());

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/api/status") => handle_status(&ctx).await,
        (&Method::GET, "/api/config") => handle_get_config(&ctx).await,
        (&Method::PUT, "/api/config") => handle_put_config(req, &ctx).await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap()),
    }
}

fn with_security_headers(mut resp: Response<Body>) -> Response<Body> {
    let h = resp.headers_mut();
    for (k, v) in [
        ("content-security-policy", CSP),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        // config and status must not linger in browser or proxy caches
        ("cache-control", "no-store"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    resp
}

fn authorized(req: &Request<Body>, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    match req.headers().get("authorization").map(|v| v.to_str()) {
        Some(Ok(s)) => {
            let given = s.strip_prefix("Bearer ").unwrap_or(s).trim();
            constant_time_eq(given.as_bytes(), token.as_bytes())
        }
        _ => false,
    }
}

async fn handle_status(ctx: &AdminContext) -> Result<Response<Body>> {
    let status = ctx.status.read().await;
    let mut services: Vec<ServiceStatus> = status
        .iter()
        .map(|(name, live)| ServiceStatus {
            name: name.clone(),
            connected: *live > 0,
        })
        .collect();
    services.sort_by(|a, b| a.name.cmp(&b.name));

    let body = serde_json::to_vec(&StatusResponse {
        mode: match ctx.mode {
            RunMode::Server => "server",
            RunMode::Client => "client",
            RunMode::Undetermine => "unknown",
        },
        services,
    })?;

    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap())
}

fn text_response(status: StatusCode, msg: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(msg))
        .unwrap()
}

async fn handle_get_config(ctx: &AdminContext) -> Result<Response<Body>> {
    let cfg = fs::read_to_string(&ctx.config_path).await?;
    match redact_config(&cfg) {
        Ok(redacted) => Ok(text_response(StatusCode::OK, redacted)),
        // Never fall back to sending the raw file
        Err(e) => Ok(text_response(StatusCode::CONFLICT, format!("{:#}", e))),
    }
}

async fn handle_put_config(req: Request<Body>, ctx: &AdminContext) -> Result<Response<Body>> {
    let body = match read_limited(req.into_body(), MAX_CONFIG_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return Ok(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("{:#}", e),
            ))
        }
    };
    let cfg_text = match String::from_utf8(body) {
        Ok(t) => t,
        Err(_) => {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "config must be valid utf-8 text".into(),
            ))
        }
    };
    let current = fs::read_to_string(&ctx.config_path).await?;
    let cfg_text =
        match restore_secrets(&cfg_text, &current).and_then(|t| Config::from_str(&t).map(|_| t)) {
            Ok(t) => t,
            Err(e) => return Ok(text_response(StatusCode::BAD_REQUEST, format!("{:#}", e))),
        };
    fs::write(&ctx.config_path, cfg_text).await?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

async fn read_limited(mut body: Body, limit: usize) -> Result<Vec<u8>> {
    let too_large = || anyhow!("config larger than {} bytes", limit);
    let declared = body.size_hint().lower() as usize;
    if declared > limit {
        bail!(too_large());
    }
    let mut buf = Vec::with_capacity(declared);
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > limit {
            bail!(too_large());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// If `line` is `KEY = "VALUE"` (optionally followed by a comment) with KEY a
/// secret key, return (KEY, byte range of the quoted VALUE including quotes)
fn secret_assignment(line: &str) -> Option<(&str, std::ops::Range<usize>)> {
    let eq = line.find('=')?;
    let key = line[..eq].trim();
    if !SECRET_KEYS.contains(&key) {
        return None;
    }
    let rest = &line[eq + 1..];
    let start = eq + 1 + (rest.len() - rest.trim_start().len());
    let quote = line[start..].chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    // basic strings may contain \" escapes; literal strings can't contain '
    let mut i = start + 1;
    let bytes = line.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quote == '"' => i += 2,
            c if c == quote as u8 => return Some((key, start..i + 1)),
            _ => i += 1,
        }
    }
    None
}

/// Table path of a `[a.b."c"]` header line, or None if `line` isn't one
fn table_header(line: &str) -> Option<Vec<String>> {
    let t = line.trim();
    if !t.starts_with('[') || t.starts_with("[[") {
        return None;
    }
    // Let the TOML parser handle quoting: "[a.b]" parses to {a = {b = {}}}
    let mut v: toml::Value = toml::from_str(t).ok()?;
    let mut path = Vec::new();
    while let toml::Value::Table(tbl) = v {
        match tbl.into_iter().next() {
            Some((k, inner)) => {
                path.push(k);
                v = inner;
            }
            None => break,
        }
    }
    Some(path)
}

/// Replace every secret value with `REDACTED`. Fails rather than leak if a
/// secret is written in a form this line-based pass doesn't recognize.
fn redact_config(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        match secret_assignment(line) {
            Some((_, range)) => {
                out.push_str(&line[..range.start]);
                out.push_str(&format!("\"{}\"", REDACTED));
                out.push_str(&line[range.end..]);
            }
            None => out.push_str(line),
        }
    }
    let parsed: toml::Value = toml::from_str(&out).context("Failed to parse the config")?;
    if let Some(path) = find_unredacted_secret(&parsed, &mut Vec::new()) {
        bail!(
            "Config has a secret at `{}` in a form the admin UI can't redact \
             (put each secret on its own `key = \"value\"` line); edit it on disk",
            path.join(".")
        );
    }
    Ok(out)
}

fn find_unredacted_secret(v: &toml::Value, path: &mut Vec<String>) -> Option<Vec<String>> {
    match v {
        toml::Value::Table(t) => {
            for (k, inner) in t {
                path.push(k.clone());
                let leaked = match inner {
                    toml::Value::String(s) if SECRET_KEYS.contains(&k.as_str()) => s != REDACTED,
                    _ => false,
                };
                if leaked {
                    return Some(path.clone());
                }
                if let Some(p) = find_unredacted_secret(inner, path) {
                    return Some(p);
                }
                path.pop();
            }
            None
        }
        toml::Value::Array(a) => a.iter().find_map(|x| find_unredacted_secret(x, path)),
        _ => None,
    }
}

/// Put back the on-disk value of every secret left as `REDACTED` in `new`
fn restore_secrets(new: &str, current: &str) -> Result<String> {
    if !new.contains(REDACTED) {
        return Ok(new.to_string());
    }
    let current: toml::Value =
        toml::from_str(current).context("Failed to parse the config on disk")?;
    let mut table: Vec<String> = Vec::new();
    let mut out = String::with_capacity(new.len());
    for line in new.split_inclusive('\n') {
        if let Some(path) = table_header(line) {
            table = path;
        }
        match secret_assignment(line) {
            Some((key, range))
                if line[range.clone()].trim_matches(|c| c == '"' || c == '\'') == REDACTED =>
            {
                let mut v = &current;
                for k in table.iter().map(String::as_str).chain(std::iter::once(key)) {
                    v = v.get(k).ok_or_else(|| {
                        anyhow!(
                            "`{}.{}` is `{}` but has no saved value to keep; enter the secret",
                            table.join("."),
                            key,
                            REDACTED
                        )
                    })?;
                }
                let original = toml::Value::String(
                    v.as_str()
                        .ok_or_else(|| anyhow!("saved `{}` is not a string", key))?
                        .to_string(),
                );
                out.push_str(&line[..range.start]);
                out.push_str(&original.to_string());
                out.push_str(&line[range.end..]);
            }
            _ => out.push_str(line),
        }
    }
    if out.contains(REDACTED) {
        bail!(
            "`{}` is left where a secret can't be restored; enter the secret",
            REDACTED
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"# comment with token = "not a secret line"
[admin]
token = "admin-secret" # inline comment

[server]
bind_addr = "0.0.0.0:2333"
default_token = 'lit\eral'

[server.transport]
type = "noise"
[server.transport.noise]
local_private_key = "priv\"key"

[server.services."my svc"]
token = "svc-secret"
bind_addr = "0.0.0.0:5202"
"#;

    #[test]
    fn redacts_every_secret_and_keeps_layout() {
        let r = redact_config(CFG).unwrap();
        for secret in ["admin-secret", "lit\\eral", "priv\\\"key", "svc-secret"] {
            assert!(!r.contains(secret), "{} leaked", secret);
        }
        assert!(r.contains("# comment with token"));
        assert!(r.contains(r#"token = "<redacted>" # inline comment"#));
        assert_eq!(r.lines().count(), CFG.lines().count());
    }

    #[test]
    fn refuses_secrets_it_cannot_redact() {
        let inline = "[server]\nbind_addr = \"x\"\nservices = { a = { token = \"s\" } }\n";
        assert!(redact_config(inline).is_err());
        let multiline = "[admin]\ntoken = \"\"\"\ns\"\"\"\n";
        assert!(redact_config(multiline).is_err());
    }

    #[test]
    fn round_trip_restores_secrets() {
        let edited = redact_config(CFG)
            .unwrap()
            .replace("0.0.0.0:5202", "0.0.0.0:5203");
        let restored = restore_secrets(&edited, CFG).unwrap();
        assert_eq!(
            restored,
            CFG.replace("0.0.0.0:5202", "0.0.0.0:5203")
                .replace("'lit\\eral'", "\"lit\\\\eral\"")
        );
        let a: toml::Value = toml::from_str(&restored).unwrap();
        assert_eq!(
            a["server"]["transport"]["noise"]["local_private_key"].as_str(),
            Some("priv\"key")
        );
        assert_eq!(a["server"]["default_token"].as_str(), Some("lit\\eral"));
        assert_eq!(
            a["server"]["services"]["my svc"]["token"].as_str(),
            Some("svc-secret")
        );
    }

    #[test]
    fn new_secret_values_pass_through_and_unknown_placeholders_fail() {
        let edited = redact_config(CFG).unwrap().replacen(
            r#"token = "<redacted>" # inline"#,
            r#"token = "new-admin" # inline"#,
            1,
        );
        let restored = restore_secrets(&edited, CFG).unwrap();
        assert!(restored.contains("new-admin"));
        assert!(restored.contains("svc-secret"));

        let added = format!(
            "{}\n[server.services.new]\ntoken = \"<redacted>\"\nbind_addr = \"0.0.0.0:1\"\n",
            redact_config(CFG).unwrap()
        );
        assert!(restore_secrets(&added, CFG).is_err());
    }

    #[test]
    fn auth_accepts_bearer_or_bare_token_only_when_equal() {
        let req = |v: &str| {
            Request::builder()
                .header("authorization", v)
                .body(Body::empty())
                .unwrap()
        };
        assert!(authorized(&req("Bearer abc"), "abc"));
        assert!(authorized(&req("abc"), "abc"));
        assert!(!authorized(&req("Bearer abd"), "abc"));
        assert!(!authorized(&req("Bearer ab"), "abc"));
        assert!(!authorized(&req("Bearer abc"), ""));
        assert!(!authorized(&Request::new(Body::empty()), "abc"));
    }
}

use crate::{config::AdminConfig, Config, RunMode};
use anyhow::{anyhow, Context, Result};
use hyper::service::{make_service_fn, service_fn};
use hyper::{body::to_bytes, Body, Method, Request, Response, Server, StatusCode};
use lazy_static::lazy_static;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Clone)]
pub struct AdminContext {
    pub mode: RunMode,
    pub bind_addr: String,
    pub token: String,
    pub config_path: PathBuf,
    pub status: Arc<RwLock<HashMap<String, bool>>>,
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

    function getToken() { return localStorage.getItem('rathole_admin_token') || ''; }
    function saveToken() { localStorage.setItem('rathole_admin_token', tokenInput.value); msg.textContent = t('tokenSaved'); setTimeout(()=>msg.textContent='',1500); }
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

    async function loadStatus() {
      try {
        const res = await api('/api/status');
        const data = await res.json();
        modeSpan.textContent = t('modeLabel') + ': ' + data.mode;
        statusBody.innerHTML = data.services.map(s => {
          const cls = s.connected ? 'ok' : 'bad';
          const text = s.connected ? t('connected') : t('disconnected');
          return `<tr><td>${s.name}</td><td><span class="status-chip ${cls}"><span class="dot"></span>${text}</span></td></tr>`;
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
    });

    {
        let mut guard = ADMIN_CONTEXT.write().await;
        *guard = Some(ctx.clone());
    }

    {
        let mut status = ctx.status.write().await;
        for name in services {
            status.insert(name, false);
        }
    }

    let bind_addr = ctx.bind_addr.parse().context("Invalid admin bind_addr")?;
    let server_ctx = ctx.clone();

    tokio::spawn(async move {
        info!("Admin UI listening at {}", server_ctx.bind_addr);
        let make_svc = make_service_fn(move |_| {
            let ctx = server_ctx.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let ctx = ctx.clone();
                    async move {
                        match handle(req, ctx.clone()).await {
                            Ok(resp) => Ok::<_, hyper::Error>(resp),
                            Err(err) => {
                                error!("{:#}", err);
                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("internal error"))
                                        .unwrap(),
                                )
                            }
                        }
                    }
                }))
            }
        });

        let server = Server::bind(&bind_addr).serve(make_svc);

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
        status.insert(name.to_string(), false);
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
        if let Some(v) = status.get_mut(name) {
            *v = connected;
        } else {
            status.insert(name.to_string(), connected);
        }
    }
}

async fn current_context() -> Option<Arc<AdminContext>> {
    ADMIN_CONTEXT.read().await.clone()
}

async fn handle(req: Request<Body>, ctx: Arc<AdminContext>) -> Result<Response<Body>> {
    if req.method() == Method::GET && req.uri().path() == "/" {
        return Ok(Response::builder()
            .header("content-type", "text/html")
            .body(Body::from(HTML_PAGE))
            .unwrap());
    }

    if !authorized(&req, &ctx.token) {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("unauthorized"))
            .unwrap());
    }

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

fn authorized(req: &Request<Body>, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    match req.headers().get("authorization") {
        Some(v) => {
            if let Ok(s) = v.to_str() {
                let prefix = "Bearer ";
                if let Some(rest) = s.strip_prefix(prefix) {
                    rest.trim() == token
                } else {
                    s.trim() == token
                }
            } else {
                false
            }
        }
        None => false,
    }
}

async fn handle_status(ctx: &AdminContext) -> Result<Response<Body>> {
    let status = ctx.status.read().await;
    let mut services: Vec<ServiceStatus> = status
        .iter()
        .map(|(name, connected)| ServiceStatus {
            name: name.clone(),
            connected: *connected,
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

async fn handle_get_config(ctx: &AdminContext) -> Result<Response<Body>> {
    let cfg = fs::read_to_string(&ctx.config_path).await?;
    Ok(Response::builder()
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(cfg))
        .unwrap())
}

async fn handle_put_config(req: Request<Body>, ctx: &AdminContext) -> Result<Response<Body>> {
    let body = to_bytes(req.into_body()).await?;
    let cfg_text =
        String::from_utf8(body.to_vec()).map_err(|_| anyhow!("config must be valid utf-8 text"))?;
    Config::from_str(&cfg_text)?;
    fs::write(&ctx.config_path, cfg_text).await?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap())
}

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
    body { font-family: sans-serif; margin: 0; padding: 16px; background: #f6f6f6; }
    .card { background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); margin-bottom: 16px; }
    textarea { width: 100%; min-height: 240px; font-family: monospace; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e5e5e5; }
    th { font-weight: 600; }
    .status { padding: 4px 8px; border-radius: 12px; font-size: 12px; }
    .ok { background: #e6ffed; color: #0c6b2b; }
    .bad { background: #ffecec; color: #a30000; }
    .actions { display: flex; gap: 8px; align-items: center; }
    input { padding: 6px 8px; font-size: 14px; }
    button { padding: 8px 12px; font-size: 14px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="card">
    <h2>管理令牌</h2>
    <div class="actions">
      <input id="token" type="password" placeholder="Bearer token" />
      <button onclick="saveToken()">保存</button>
    </div>
  </div>
  <div class="card">
    <h2>服务状态</h2>
    <div id="mode"></div>
    <table>
      <thead><tr><th>服务名</th><th>状态</th></tr></thead>
      <tbody id="status-body"></tbody>
    </table>
  </div>
  <div class="card">
    <h2>配置</h2>
    <textarea id="config"></textarea>
    <div class="actions">
      <button onclick="loadConfig()">刷新配置</button>
      <button onclick="saveConfig()">保存并热重载</button>
      <span id="message" style="font-size:13px;color:#555;"></span>
    </div>
  </div>
  <script>
    const tokenInput = document.getElementById('token');
    const statusBody = document.getElementById('status-body');
    const modeSpan = document.getElementById('mode');
    const cfg = document.getElementById('config');
    const msg = document.getElementById('message');

    function getToken() { return localStorage.getItem('rathole_admin_token') || ''; }
    function saveToken() { localStorage.setItem('rathole_admin_token', tokenInput.value); msg.textContent = 'Token 已保存'; setTimeout(()=>msg.textContent='',1500); }
    tokenInput.value = getToken();

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
        modeSpan.textContent = '运行模式：' + data.mode;
        statusBody.innerHTML = data.services.map(s => {
          const cls = s.connected ? 'ok' : 'bad';
          const text = s.connected ? '已连接' : '未连接';
          return `<tr><td>${s.name}</td><td><span class="status ${cls}">${text}</span></td></tr>`;
        }).join('');
      } catch (e) { msg.textContent = '加载状态失败：' + e.message; }
    }

    async function loadConfig() {
      try {
        const res = await api('/api/config');
        cfg.value = await res.text();
        msg.textContent = '配置已加载';
        setTimeout(()=>msg.textContent='',1500);
      } catch (e) { msg.textContent = '加载配置失败：' + e.message; }
    }

    async function saveConfig() {
      try {
        await api('/api/config', { method: 'PUT', body: cfg.value });
        msg.textContent = '已保存，热重载中';
        setTimeout(()=>msg.textContent='',1500);
      } catch (e) { msg.textContent = '保存失败：' + e.message; }
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

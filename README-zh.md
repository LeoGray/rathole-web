# Rathole Web

Rathole Web 是 Rathole 的 Web 控制平面，提供基于浏览器的管理、监控和配置能力。

本项目在上游 Rathole 之上做了少量、范围明确的扩展，用于暴露运行时状态和控制接口，同时保持与上游的紧密对齐。

[English](README.md) | [简体中文](README-zh.md)

<!-- TOC -->

- [Rathole Web](#rathole-web)
  - [与 Rathole 的关系](#与-rathole-的关系)
  - [Features](#features)
  - [Quickstart](#quickstart)
  - [Configuration](#configuration)

<!-- /TOC -->

## 与 Rathole 的关系

Rathole Web 不是为了取代 Rathole 的分叉。

它引入了少量核心扩展，用于暴露 Web UI 所需的运行状态和控制钩子；这些扩展是最小化的、显式的，并与核心逻辑保持隔离。

上游项目： [rapiz1/rathole](https://github.com/rapiz1/rathole)。

## Features

- **Web 控制平面** 浏览器界面读取/写入配置、触发热重载、查看服务连通性，并通过管理 token 保护。

以下能力来自上游 Rathole：
- **高性能** 具有更高的吞吐量，高并发下更稳定。见[Benchmark](#benchmark)
- **低资源消耗** 内存占用远低于同类工具。见[Benchmark](#benchmark)。[二进制文件最小](docs/build-guide.md)可以到 **~500KiB**，可以部署在嵌入式设备如路由器上。
- **安全性** 每个服务单独强制鉴权。Server 和 Client 负责各自的配置。使用 Noise Protocol 可以简单地配置传输加密，而不需要自签证书。同时也支持 TLS。
- **热重载** 支持配置文件热重载，动态修改端口转发服务。HTTP API 正在开发中。

## Quickstart

1. 编译本仓库：
   ```bash
   cargo build --release
   ```
2. 在原有 Rathole 配置的基础上加入管理配置：
   ```toml
   [admin]
   bind_addr = "127.0.0.1:2334"
   token = "strong-admin-token"
   ```
   或使用环境变量覆盖：`RATHOLE_ADMIN_TOKEN`、`RATHOLE_ADMIN_BIND`。
3. 运行：
   ```bash
   ./target/release/rathole config.toml
   ```
4. 浏览器访问 `http://<bind_addr>/`，输入管理 token，可查看服务连通性、读取/保存配置（保存后自动热重载）。

未配置 `[admin]` 或环境变量时，行为与上游 Rathole 相同（无 Web 控制平面）。上游发布包可参考 [release](https://github.com/rapiz1/rathole/releases)。

## Configuration

Admin 配置示例：
```toml
[admin]
bind_addr = "127.0.0.1:2334"
token = "strong-admin-token"
```
环境变量覆盖：`RATHOLE_ADMIN_TOKEN`、`RATHOLE_ADMIN_BIND`。

Server/Client 其他配置与上游一致，请参考上游文档或本仓库的 `examples/`、`docs/transport.md`。

示例配置（含管理端与一个转发服务）：
```toml
[admin]
bind_addr = "127.0.0.1:2334"
token = "strong-admin-token"

[server]
bind_addr = "0.0.0.0:2333"

[server.services.my_nas_ssh]
token = "use_a_secret_that_only_you_know"
bind_addr = "0.0.0.0:5202"
```

# 启动 Cookie 守护（@local/dsh-auth-cookie-guard）

修复 DSH 桌面版「固定 profile 启动约 72 次后永久报 `desktop welcome: Web authentication failed`」的问题。

## 症状

- 固定 profile（固定 `userData`）连续启动约 72 次之后，桌面端再也进不去，日志里是 `desktop welcome: Web authentication failed`（`app.asar/lib/main.js:8886` 的 `connectDesktopWelcome`）。
- 重启、撤销授权、重装都无效，只有换掉整个 profile（也就是换掉 Chromium 的 cookie 库）才能恢复。

## 根因

1. Host 每次启动都绑定随机端口；浏览器会话 cookie 按授权方命名：
   `dsh-auth-<base64url(sha256(host:port))>`（`dsh-client-connection/lib/index.js:277`、`:335-337`）。
2. 浏览器按**域名**存 cookie，端口不进键。于是每启动一次，`127.0.0.1` 上就多一条约 173 字符、`Max-Age` 30 天的持久 cookie，且没有任何代码删除它们。
3. Host 建监听器时没有覆盖头部预算——`createServer(listener)`（`dsh-host-webserver/lib/index.js:412`）——因此沿用 Node 默认的 `maxHeaderSize = 16384` 字节。
4. 第 71 条累积后 `Cookie` 头约 16184 字节，本轮再下发 1 条即约 16411 字节，超过 16384，Node 直接返回 `431`；客户端把它当成认证失败。此后每次启动都超过上限，而 431 的请求根本到不了应用层，也就没有任何机会清理——故障是纯累积型且不可自愈的。

## 插件做了什么

两层防护，缺一不可：

| 层 | 行为 | 默认值 |
| --- | --- | --- |
| 头部预算 | 在 `webServer` 服务就绪后把 `server.maxHeaderSize` 提升到 64 KiB | `maxHeaderBytes: 65536` |
| 退休旧 cookie | 每个请求检查 `Cookie` 头里的 `dsh-auth-<43 位 base64url>`；解析 cookie 值里的 `issuedAt`，只保留最新 `keep` 条 + 当前端口那一条，其余用 `Max-Age=0; Path=/` 从浏览器 jar 删除 | `keep: 4` |

几点设计取舍：

- **为什么两层都要**：只提升预算，约 350 次启动后依旧会撞墙（只是把 72 次变成 350 次）；只清理而不提升预算，则清理逻辑永远跑不到——431 在 Node 的 HTTP 解析层就被拒了，请求不会进入监听器。
- **为什么不验证签名**：`issuedAt` 只用于给**调用者自己的** cookie 排序，删掉的也只是调用者自己在请求里带上的 cookie，不涉及认证判断，所以无需签名密钥。
- **为什么保留当前端口那条**：即使 `keep` 配得很小、或系统时钟回拨，也不会把正在使用的那条 cookie 删掉。
- **为什么用 `Max-Age=0` 而不是改名或重写**：cookie 名与端口/协议绑定（`requestAudience`），改名会让认证查不到；重签名需要密钥。删除是唯一不改变语义的收敛方式。
- **对异常格式零影响**：只匹配 `dsh-auth-` + 43 位 base64url 的精确形状。若未来 cookie 格式变化，退化结果是「预算提升、不再清理」，而不是破坏会话。
- **不会越界**：只处理 `webServer` 自己的局域网/本机监听器；其它 profile 的 host 有独立 cookie 库，互不影响。
- **64 KiB 为什么够**：Chromium 对单域名有条数上限（180 条），每条 minted cookie 约 173 字符，理论上限约 33 KB，已经落在 64 KiB 之内。即使一个已经被锁死的 jar 条数拉满，也能在第一次握手时被放行，并当场收敛。

## 配置

在 profile 的 patch 层给这一行加 `config` 即可（`maxHeaderBytes` 会被夹到 16 KiB–1 MiB，`keep` 到 1–64）：

```yaml
- id: auth-cookie-guard
  name: '@local/dsh-auth-cookie-guard'
  config:
    maxHeaderBytes: 131072
    keep: 4
```

一般不需要改。若某台机器上 cookie 已经多到超过 64 KiB（约 350 次启动），把 `maxHeaderBytes` 临时调到 `262144`，启动一次让清理跑完，再调回默认值即可。

## 安装与卸载

- 安装：在插件管理中作为 bundle 安装（源码目录即本仓库），工具会把它写进 profile 的 `package.json`（`dsh.profile.bundles` 与 `link:` 依赖）；本 bundle 自带的 `cordis.patch.yml` 作为独立层插入那一行，profile 自己的 `cordis.patch.yml` 不需要任何改动。不要手改 profile 文件。
- 生效方式：安装时宿主会重载组合，插件当场 apply，无需重启桌面端；之后每次启动同样自动生效。
- 卸载：在插件管理中移除该 bundle，重启桌面端；卸载后会恢复监听器的原始头部预算（插件在 dispose 时还原）。
- 本插件只有 Host 端，没有浏览器端资源，也没有 service / tool / event。

## 验证

用一个真实的 `node:http` 服务器模拟 71 条旧 cookie + 本轮 1 条（构造方式与报告一致）：

```
cookie header bytes: 16414
BEFORE: {"status":431}                       # 安装前：与线上故障同因
[info] auth-cookie-guard: listener header budget 65536 bytes, keeping 4 launch cookie(s)
[info] auth-cookie-guard: retired 68 launch cookie(s), kept 4
AFTER: status 200 deletions 68               # 安装后：握手通过，并当场清掉 68 条
kept names: 4 (current kept)                 # 最新 4 条保留，当前端口那一条保留
maxHeaderSize now: 65536
AFTER PRUNE: 200 deletions 0                 # 第二次请求不再产生删除头（幂等）
maxHeaderSize restored: undefined            # dispose 后还原
```

线上验证（对本机已安装、正在运行的宿主直接探测，插件安装后即时生效）：

```
big header 20KB:  {"status":401}            # 提升预算前这里是 431
71 cookies:       401 deletions: 68         # 当场退休 68 条，保留最新 4 条
```

第一行说明请求已经进入应用层（401 是未认证的正常响应，而不是 Node 在解析层回的 431），即 `maxHeaderSize` 已抬到 64 KiB；第二行说明裁剪逻辑在真实请求上生效。宿主日志同时会打印
`auth-cookie-guard: listener header budget 65536 bytes, keeping 4 launch cookie(s)` 与
`auth-cookie-guard: retired N launch cookie(s), kept 4`，此后无论重启多少次都不再累积。

## 环境

Windows 11、DSH 0.2.1-rc.3、Electron 44.7.0、Node 24.21.0（本机复现用 Node 24.18.0）。`server.maxHeaderSize` 在运行时赋值即对后续连接生效，这一点已在 Node 24 上实测（431 → 200，70000 字节 → 431）。

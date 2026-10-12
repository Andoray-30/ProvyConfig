# 编译、部署与维护

## Docker（推荐）

需要 Linux x86_64、Docker Engine、Compose 插件和两个可用新域名。运行 `docker compose version` 核对插件；本仓库不替你安装宿主依赖。

```bash
./deploy.sh init
# 编辑 config.yaml：订阅、domains.gateway / subscription、acme_email。
./deploy.sh start
./deploy.sh status
```

等价手动流程：`docker compose build dispatch` → `docker compose run --rm --no-deps dispatch prepare` → `docker compose --profile relay up -d`。这三个步骤在家庭服务器执行，不需要在云服务器打包。

Dockerfile 使用 Python 3.11 和 PyYAML 6.0.3；官方 Mihomo v1.19.30 amd64-v1 由 tools/fetch_engine.py 获取，两级哈希校验失败立即停止。官方发布及来源见 [vendor/NOTICE.md](../vendor/NOTICE.md)。不执行下载到的未知安装脚本，不重新编译 Go 内核。

首次准备没有规则缓存，需能下载 MetaCubeX 的国内／海外／Google/Gemini 规则与 Google 官方服务 IP 数据，扣除 Google Cloud 客户分配范围后编译为第六份规则。下载、原生校验、完整发布是一个事务；失败可以修好网络后重新 prepare，不伪造规则就绪。

本包使用 Linux host 网络，控制器／健康端口仍绑定回环；没有 privileged、NET_ADMIN、宿主 Docker socket 或宿主系统配置挂载。容器 root 配合只读根文件系统和 cap_drop ALL，仅保留低端口绑定能力；host 网络仍意味着必须审计你运行的源码。

## Python 直接运行

筛选／分发程序无需编译。Ubuntu/Debian 需要 Python 3、venv、curl、openssl、CA 证书；仅在家庭机器明确决定安装依赖后，使用其包管理器补齐。已有宿主代理／内核不会被自动覆盖。

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo python3 tools/fetch_engine.py --output /usr/local/bin/mihomo
./deploy.sh init
# 编辑配置。先选 local-test；完整模式需你的 Caddy 和正确证书。
.venv/bin/python -B app/portable.py prepare
.venv/bin/python -B app/portable.py run
```

下载工具遇到相同内核只验证、不重写；已有不同内核则拒绝覆盖，需你决定独立部署或精确备份后处理。原生规则编译依赖 `/usr/local/bin/mihomo`，不能只改 Gateway 的环境变量却遗漏规则编译。

非 Docker 完整部署推荐 tls.mode=manual，自有 Caddy 使用 data/caddy-config/Caddyfile；manual 的一份证书须同时覆盖两个域名。auto 配置的存储根 `/data` 是容器路径，不要未经适配直接给宿主 Caddy。仓库不会自动创建 systemd／cron 常驻任务。

## 配置和私有数据

- config.yaml：上游订阅、子域名、入口和 TLS，0600，Git 与 Docker 上下文均排除。
- data/runtime、data/secrets：家庭候选、原始输入、健康／资格记录和独立认证信息，不能清空或分享。
- data/rules：每日完整规则包，失败保留上次可用包，15 分钟重试。
- data/caddy、certs：自动／手工证书及私钥，不提交 Git。
- data/handoff/subscription-url.txt：完整模式家庭订阅地址，含私有令牌。

初始节点从零核验；不把阿里云状态／证书／令牌复制进家庭部署。删除一个 provider 角色后，适配器不会继续选用该角色的缓存候选。

默认内部端口 offset=10000：28190 核验、28192 内部订阅、29190 控制器、284xx/286xx VLESS、31000–31999 逐节点探测，均回环监听。不要公开这些端口；公开 TCP 80/443 与 UDP 443 由你核对家庭映射。初始化后不能直接改 offset；需新独立数据目录。

## 验证

已安装校验内核和依赖后，可按顺序运行：

```bash
PYTHONPATH=app python3 -B -m unittest discover -s tests -q
docker compose config --quiet
sh -n deploy.sh
```

回归是合成数据和回环隔离测试，不使用真实订阅。不要与镜像构建／大下载并行在小云主机上验收；首次并行容器测试曾出现资源争用下超时，构建结束后宿主及 Python 3.11/PyYAML 6.0.3 容器各 211 项通过。纯源码版的新增规则引导测试另以本版验证记录为准，不能套用旧大包验收数字。

实际家庭验收：手机移动网络检查 HTTPS 与 HY2；在已认证校园网验证校园访问及 WebRTC；同原始节点／同目标／同测试方式重复 benchmark，对比成功率与中位／慢请求耗时。关闭 IPv6 后仍低延迟，说明该样本不依赖 IPv6，不能单凭这点认定云厂商或提供商对机房 IP 限制。

## 更新与停止

上游 URL 修改后重新创建 dispatch；域名／端口／TLS 修改后 prepare 并重新创建两个容器。规则更新不重启 Gateway，客户端更新订阅取得最新规则版本。

`./deploy.sh stop` 仅停止本仓库容器，不使用 -v，不删 data。升级前将 config.yaml、data 和旧源码权限安全备份到你的受控目录；不上传 GitHub。恢复代码后重新核验，不恢复过时资格冒充可用。不改已有 DNS、防火墙、SSH、代理或其他服务。

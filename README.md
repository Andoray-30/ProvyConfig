# 独立节点分发 · 源码部署

Linux x86_64。保留已验收的国内／海外分流、校园当前网络 DNS、Google/Gemini/Antigravity、常见 WebRTC 防漏，以及全量候选核验、稳定性隔离和自动恢复。

这是纯源码仓库：不提交真实订阅、节点账号、令牌、私钥、运行状态、二进制内核、规则数据库或历史部署大包。

## 家庭服务器部署

克隆仓库后，在仓库目录执行：

```bash
./deploy.sh init
# 用编辑器修改 config.yaml；真实订阅仅存在该私有文件，权限 0600。
./deploy.sh start
./deploy.sh logs
./deploy.sh status
```

`init` 不覆盖已有配置。填入 providers.residential（苏菲原始订阅，必填），可选 providers.datacenter，以及两个新子域名、ACME 邮箱。`start` 在家庭机器构建 Docker 镜像并启动本仓库服务；不会修改宿主 DNS、防火墙、路由器或现有代理。

默认 `mode: relay` 提供 HTTPS 订阅、VLESS/WS/TLS 和 HY2/UDP。Caddy 首次签发证书，分发服务等待后从零核验候选；尚无合格节点时订阅返回 503。就绪后在家庭服务器本地读取 `data/handoff/subscription-url.txt`，其中是独立的家庭订阅地址。不要把私有令牌贴到日志或 GitHub。

详见 [新子域名与网络要求](docs/DOMAINS.md)，两条新 DNS 记录均设 DNS-only，不改阿里云现役入口。

## 不需要“编译筛选程序”

服务是 Python，源码可以直接运行；Docker build 仅准备运行环境，不编译 Mihomo。构建时从官方发布下载固定内核，校验压缩文件及可执行文件 SHA256；首次 prepare 在家庭端下载／生成六份规则，原生校验完整成功才发布。失败不会启动一份缺规则的订阅。

没有离线大包：首次安装需要能访问 Docker 镜像、PyPI、官方 Mihomo 发布与规则源。已有 Docker Compose 即可；不在阿里云继续构建／导出镜像。

## 先比较家庭线路

将 config.yaml 的 mode 改为 `local-test`，无需先准备域名或证书：

```bash
./deploy.sh test
./deploy.sh status
./deploy.sh benchmark JP 3
```

测试模式不开放公网 HY2、不提供手机可导入订阅；保留同一筛选和核验过程。benchmark 对所有苏菲一倍日本 HY2 候选发送两目标各三次小请求，比较本机直连原始上游的成功率和请求耗时，不切换选择器或修改健康历史。结果不是 ping，也不包含手机到家庭服务器的中转延迟。

切换模式前先 `./deploy.sh stop`；再准备 relay 域名并 `./deploy.sh start`。stop 不删除持久数据。

## 结构与维护

入口是 `app/portable.py`，不要运行原始 `app/app.py` 的阿里云 CLI。八个核心模块为原验收源码快照；适配器配置化域名／端口／路径与拉取方式，不放宽选路门槛。VLESS 保留原候选逻辑；HY2 每国最多一条，只接苏菲来源的一倍 HY2，机房订阅 HY2 不进入这个池。

具体 [依赖、源码运行、验证与升级](docs/DEPLOYMENT.md)。规则每 24 小时更新，失败保留旧完整包；候选约每轮结束后 90 分钟重新拉取，不复用阿里云健康记录。国内 DIRECT 仍由客户端本地连接。

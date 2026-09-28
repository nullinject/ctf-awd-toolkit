# CTF AWD Toolkit · 离线练习与比赛运维工具包

**离线练习入口：[OFFLINE.md](OFFLINE.md)**。快速验证整轮流程：`python3 lab/verify.py`；手动启动：`python3 lab/run.py`。核心演练只用 Python 标准库和本机网络。

用于比赛规则允许的主机与服务。Python 3.10+，核心工具只使用标准库；主机排查脚本面向 Linux。先在本地副本演练，再用于比赛环境。没有题目源码、二进制和平台接口时，无法验证通用漏洞利用或一键加固是否适用；这套工具先完成比赛的通用运维和提交流程。

## 获取工具包

```bash
git clone https://github.com/nullinject/ctf-awd-toolkit.git
cd ctf-awd-toolkit
python3 -m unittest discover -s tests -v
python3 scripts/verify_offline.py
```

不需要第三方 Python 包。离线练习使用本机回环地址和模拟 flag；
真实比赛配置、凭据、抓包、备份及运行状态不随仓库发布。

## 快速开始

```bash
cp awd.example.json awd.json
python3 awd.py --help
# 编辑 awd.json，填写明确允许访问的目标和正确的 flag 正则
python3 awd.py health
python3 awd.py health --watch 10
```

目标只从配置读取，不展开网段。HTTP 不跟随重定向，HTTPS 校验证书；TCP 检查只说明端口可连接，不代表业务正常。HTTP 可配置状态码和响应关键字。输出为 JSON Lines，可重定向保存；watch 使用 Ctrl+C 停止。

## 开赛操作顺序

1. 确认比赛规则、轮次、flag 生命周期、允许的网络范围、提交频率以及禁止改动的文件。记录裁判检测的接口和必需业务功能。
2. 查看服务、监听端口、进程、定时任务和启动配置，先留证据。将源码、程序、配置及数据库分别备份到 Web 根目录外；重要备份另存一台机器。
3. 在确认可信的副本上建立文件基线。已失陷目录的基线只能记录现状，不能证明文件干净。
4. 跑通首页、登录、上传等关键业务以及 Pwn 正常交互。再做小范围修复，每次改动后复测并准备回滚。
5. 持续巡检、比对文件变更、查看访问日志，核对队列和平台计分结果。

## 文件基线与备份恢复

以下路径是示例，替换为自己的目录；输出父目录须预先存在并限制访问。

```bash
python3 awd.py baseline /srv/challenge -o /srv/evidence/clean.baseline.json --exclude uploads --exclude cache
python3 awd.py diff /srv/evidence/clean.baseline.json
python3 awd.py audit /srv/challenge
python3 awd.py backup /srv/challenge -o /srv/evidence/web-before.tar.gz
python3 awd.py restore /srv/evidence/web-before.tar.gz /srv/restore-check --sha256 BACKUP_SHA256
```

baseline 记录普通文件哈希、权限、所有者和软链接目标；不记录目录权限、ACL、扩展属性。`--exclude` 按路径组件名称排除，可重复使用。diff 发现新增、删除或变更返回 1；无变更返回 0。audit 只做可疑 PHP 调用、全局可写和 SUID/SGID 的启发式检查，不自动删除文件，也不是完整查杀工具。

备份只包含普通文件和目录，跳过软/硬链接及特殊文件并输出清单，不保留 ACL、扩展属性或数据库事务一致性。运行期间变化的文件可能产生不一致备份，应使用比赛允许的快照或维护窗口。数据库另用对应数据库的逻辑导出工具备份，不直接复制运行中的数据目录。

恢复只写入尚不存在的新目录，拒绝路径穿越、链接、特殊文件和重复成员；默认解压总大小限制为 2 GiB。输出位于 `恢复目录/data`，所有者为执行用户，清除 SUID/SGID。确认文件、权限、业务与备份校验和后再手动切换服务目录；解压中断可能留下部分目录，不要将其当作完整恢复。

## flag 提取、队列与提交

```bash
python3 awd.py extract ./result.txt ./other-result.txt
printf '%s\n' 'flag{example_12345678}' | python3 awd.py extract -
python3 awd.py queue
python3 awd.py submit
```

从你已取得的输出中提取 flag；SQLite 按完整 flag 去重。不要在真实比赛队列中加入示例 flag。正则按赛事格式修改，尽量精确；文本输入应来自可信的有限大小文件。

提交适配器为 JSON POST：`flag_field` 指定 flag 字段，`extra_fields` 添加题目编号等固定字段。认证 token 从 `token_env` 指定的环境变量读取；默认使用 `Authorization: Bearer ...`。`success_json_field` 支持 `data.success` 这样的嵌套字段，同时严格匹配 HTTP 状态、JSON 类型和值。表单、Cookie、多题目动态字段或签名接口需要按照实际比赛 API 另行适配。

```bash
# Bash 下隐藏输入 token，避免直接写入脚本或命令历史
read -rsp 'AWD token: ' AWD_TOKEN; echo
export AWD_TOKEN
# 填写提交地址并核对平台文档/一条测试响应后执行
python3 awd.py submit --send --limit 20
unset AWD_TOKEN
```

没有 `--send` 只显示待提交数量。提交前将记录标记 inflight，成功后标记 accepted；失败、不明确的响应标记 review，并停止本批提交。网络超时可能已经被平台接收，不自动重试。中断遗留的 inflight 或 review，应先核对平台记录，确认需要重发时才使用 `python3 awd.py requeue '实际flag'`。不支持自动按轮次过期、429 退避或长期常驻提交；每次调用是有限批次。

`.awd` 含明文 flag，采集报告可能含进程参数和内部地址，须限制访问，不要公开提交到仓库。配置、状态和备份已加入 gitignore。

## Linux 现场排查与流量留存

```bash
bash scripts/triage.sh /srv/evidence/triage-round1
# 只抓自己比赛服务对应的接口和端口；需要 tcpdump 与抓包权限
sudo tcpdump -i eth0 -nn -s 256 -C 10 -W 5 -w /srv/evidence/service.pcap 'tcp port 8080'
```

triage 收集进程、监听、连接、服务、定时器、当前用户 crontab、登录和防火墙信息，各项失败写入 status.txt；它不会修改配置，也不代表已覆盖全部持久化位置。另查 `/etc/cron*`、服务 unit、应用插件与上传目录。tcpdump 以前台方式运行，Ctrl+C 停止，轮转保留约 5 个 10 MB 文件；256 字节截断可能不足以重建请求。只在规则允许时抓包，并确认磁盘空间和证据访问权限。

## Web 修复检查项

| 场景 | 修复方向 | 必须复测 |
|---|---|---|
| SQL 注入 | 参数化查询，表名/排序等结构项用白名单 | 登录、查询、分页 |
| 命令注入 | 改用库函数；进程调用使用参数数组且验证参数 | 原有合法输入与错误处理 |
| 文件包含/读取 | 固定根目录，规范化后验证范围，处理符号链接 | 正常下载、模板加载 |
| 上传执行 | 独立上传目录，禁止该目录脚本执行，校验类型与内容 | 上传、图片访问、裁判流程 |
| 反序列化 | 使用安全数据格式，移除不可信对象构造 | 会话与数据读写 |
| 弱口令/暴露配置 | 按规则更换相关凭据并同步业务配置 | DB 连接、后台与裁判认证 |
| 可疑文件/进程 | 先保留证据，确认入口和可信恢复源后修复 | 服务重启与正常请求 |

不要直接对整个站点 `chmod -R 777` / `chmod -R 000`、禁止所有上传、清空防火墙或盲目批量 kill。权限、解释器禁用函数和防火墙规则必须结合实际服务账户与裁判访问方式设计。

## Pwn 检查与防守

```bash
bash scripts/pwn-inspect.sh ./challenge > binary-report.txt
```

脚本使用 file、sha256sum、readelf 静态检查，不执行二进制。Linux 需安装 file/binutils；缺失工具会明确提示。记录 ELF 架构、解释器、依赖、NX、PIE、RELRO 和 canary 线索；符号线索不等于所有函数都受保护。不要对不可信程序使用 `ldd`，先用 `readelf -d` 查看依赖。

保存原始二进制、libc/loader、启动参数和服务配置。使用匹配比赛环境的隔离副本复现交互和崩溃；有源码时优先修复读写边界、格式化字符串、生命周期和整数溢出，再验证协议兼容。只改编译选项不能修复现有逻辑漏洞，无源码二进制补丁需针对反汇编和实际输入单独验证。

## 验证

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile awd.py
bash -n scripts/triage.sh scripts/pwn-inspect.sh
```

测试用本机临时 HTTP 服务验证巡检、不跟随重定向、提交成功判定及失败不自动重发，并验证文件变更、去重、备份恢复和危险归档拒绝。真实裁判接口、实际题目协议及 Linux 现场命令须在比赛环境另行验证。

## 许可证

[MIT License](LICENSE) · [安全与数据说明](SECURITY.md)

# 离线演练：从启动到完成一轮

## 1. 最小环境

需要 **Python 3.10+（含 sqlite3）**。核心演练不依赖 pip、Docker、云服务或互联网；Web、TCP 和裁判服务都只监听 `127.0.0.1`。支持 macOS/Linux，Linux 现场排查和 ELF 工具另需在 Linux 上准备。

在本工具包目录运行：

```bash
python3 scripts/offline_check.py
python3 lab/verify.py
```

可进一步运行 `python3 scripts/verify_offline.py`：先验证 Python 网络审计钩子能拒绝外部地址与 DNS 查询，再在该限制下执行完整演练（包括子进程中的主脚本），确认没有外部网络访问尝试。这是针对本工具 Python 代码的检查，不是系统防火墙隔离，也不改动电脑网络设置。

第二条命令自动创建临时目录并使用系统分配的空闲端口，完成巡检、备份、漏洞复现、修复、业务复测、文件变更检测、恢复、TCP 交互、flag 去重和模拟提交；输出 `"ok": true` 才表示完整演练通过。结束后停止服务并清理本次临时数据。

**这条命令不会下载任何内容，但在联网电脑上运行成功不等于已经实测物理断网。** 赛前关闭互联网连接后重新运行。核心可在 macOS 练习，真实 Pwn 的 ELF、libc 和调试仍应在架构匹配的 Linux 环境演练。

## 2. 手动演练

终端 A 启动（保持前台，Ctrl+C 停止）：

```bash
python3 lab/run.py
```

首次创建 `.awd-lab`，默认 Web 18080、TCP 19999、裁判 18081。不会覆盖已有练习目录；下一轮用 `--directory .awd-lab-round2`。端口占用可指定新端口，或全部设为 0 自动分配；以启动输出和生成配置为准。以下步骤使用默认端口和目录。

终端 B：

```bash
python3 awd.py -c .awd-lab/awd.json health
python3 awd.py baseline .awd-lab/web -o .awd-lab/before.baseline.json
python3 awd.py backup .awd-lab/web -o .awd-lab/before.tar.gz
```

生成的配置独立于真实比赛配置，token 和 flag 每次新建环境时随机生成。查看配置可以获得全部服务地址。模拟平台不模拟轮次过期、SLA 扣分或限流，评分保存在当前进程内。

### Web：复现、修复、业务复测

练习代码位于 `lab/run.py` 的 `/download` 处理分支。初始 `policy.txt` 为 vulnerable，错误地允许访问公开目录的上级练习目录。下面的请求只针对本机练习题，并将获得的响应保存供后续提取：

```bash
python3 - <<'PY'
import urllib.request
from pathlib import Path
url = 'http://127.0.0.1:18080/download?name=../flag.txt'
body = urllib.request.urlopen(url, timeout=3).read()
Path('.awd-lab/web-result.txt').write_bytes(body)
print(body.decode())
PY
```

修复练习策略：

```bash
python3 - <<'PY'
from pathlib import Path
Path('.awd-lab/web/policy.txt').write_text('fixed\n')
PY
python3 awd.py diff .awd-lab/before.baseline.json
```

diff 应返回 1 并报告 policy.txt 改动。再次请求私有 flag 应得到 HTTP 403；正常下载必须继续成功：

```bash
python3 - <<'PY'
import urllib.request
import urllib.error
for name, expected in [('welcome.txt', 200), ('../flag.txt', 403)]:
    try:
        with urllib.request.urlopen('http://127.0.0.1:18080/download?name=' + name, timeout=3) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    assert status == expected, (name, status)
    print(name, status)
PY
```

这里通过策略文件切换提供可重复练习；真实题目需修改对应源码并确认生效。模拟题额外限制在自己的 web 目录内，不允许通过请求读取系统目录。

### TCP：交互、记录与提交

TCP 是协议模拟器，`FLAG` 是专门设置的练习命令，不是二进制漏洞利用。

```bash
python3 - <<'PY'
import socket
from pathlib import Path
with socket.create_connection(('127.0.0.1', 19999), timeout=3) as s:
    with s.makefile('rwb') as f:
        print(f.readline().decode().strip())
        f.write(b'FLAG\n')
        f.flush()
        Path('.awd-lab/tcp-result.txt').write_bytes(f.readline())
PY
python3 awd.py -c .awd-lab/awd.json extract .awd-lab/web-result.txt .awd-lab/tcp-result.txt
python3 awd.py -c .awd-lab/awd.json queue
python3 awd.py -c .awd-lab/awd.json submit
export AWD_TOKEN="$(cat .awd-lab/token.txt)"
python3 awd.py -c .awd-lab/awd.json submit --send
python3 awd.py -c .awd-lab/awd.json queue
```

预期 accepted 为 2。查看模拟积分：

```bash
python3 - <<'PY'
import os, urllib.request
r = urllib.request.Request('http://127.0.0.1:18081/score', headers={'Authorization': 'Bearer ' + os.environ['AWD_TOKEN']})
print(urllib.request.urlopen(r, timeout=3).read().decode())
PY
unset AWD_TOKEN
```

预期 2 个 flag、200 分。错误 token 返回 401；错误 flag 的 JSON success 为 false；重复提交同一 flag 不重复得分。

### 恢复练习

```bash
python3 awd.py restore .awd-lab/before.tar.gz .awd-lab/restore-check
```

恢复文件位于 `.awd-lab/restore-check/data`，不会覆盖当前服务。原始备份的 policy 是 vulnerable，恢复后还需要重施已验证修复；“恢复成功”不代表漏洞已经修复。

## 3. 真正的 C 二进制练习（可选，需编译器）

`lab/pwn_echo.c` 是独立 stdin 程序，含未限制长度的输入练习；不由 TCP 服务执行。建议在自己的 Linux 虚拟机副本中编译、检查、调试：

```bash
mkdir -p .awd/pwn
cc -O0 -g -Wall -Wextra lab/pwn_echo.c -o .awd/pwn/echo-vulnerable
cc -O0 -g -Wall -Wextra -DFIXED lab/pwn_echo.c -o .awd/pwn/echo-fixed
printf 'alice\n' | .awd/pwn/echo-fixed
bash scripts/pwn-inspect.sh .awd/pwn/echo-fixed
```

练习目标：定位输入边界问题，理解栈对象大小，比较修复前后正常输入行为；验证修复版超长输入返回错误。未修复版触发溢出后行为未定义，不保证在所有系统上以同样方式崩溃。编译器默认保护没有被人为关闭。

macOS 编译出的是 Mach-O，不能用它替代 Linux ELF 分析。工具包不附 Linux 镜像、GDB、pwntools、Python 安装包或多架构 libc。它们需要赛前在你的目标 Linux 虚拟机中安装并断网验证；本包核心演练无需它们。

## 4. 导出与携带

```bash
mkdir -p dist
python3 scripts/pack_offline.py dist/awd-offline.zip
```

打包仅包含明确列出的源码、测试、配置模板和文档，不包含真实 awd.json、练习 token、flag、数据库或日志。输出已有时会拒绝覆盖。解压后进入 `awd-offline` 目录，检查文件完整性：

```bash
python3 - <<'PY'
import hashlib, json
from pathlib import Path
manifest = json.loads(Path('SHA256.json').read_text())
for name, expected in manifest.items():
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, name
print('All bundled files verified')
PY
python3 scripts/offline_check.py
python3 lab/verify.py
```

哈希清单检测拷贝损坏，不提供发布者身份认证。离开联网环境前，至少保留两份工具包，并实际启动已准备好的 Linux 虚拟机。现场拿题后，复制配置模板再填写局域网目标；不要把练习端口、token 或 flag 格式照搬到比赛。

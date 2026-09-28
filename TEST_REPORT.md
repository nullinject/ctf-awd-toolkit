# 离线工具包测试记录

测试环境：macOS ARM64，Python 3.12.11。此次未修改系统网络设置。

## 发现和修复

- `/download?name=%00` 的路径解析异常原本造成连接中断；现返回 HTTP 400。
- 非 ASCII Authorization 原本使字符串常量时间比较抛异常；现拒绝认证并返回 HTTP 401。
- 两处均先通过新增测试复现，再修复并通过回归测试。

## 验证命令

```bash
python3 -m unittest discover -s tests -v
python3 scripts/verify_offline.py
python3 -m py_compile lab/run.py scripts/verify_offline.py scripts/pack_offline.py tests/test_lab.py
```

14 项测试通过，包含文件基线、备份恢复、危险归档拒绝、HTTP/TCP 巡检、提交去重、认证与坏请求、符号链接边界、真实子进程启动和 Ctrl+C 停止、已有目录拒绝覆盖、端口冲突后的监听资源释放，以及完整模拟一轮。

Python 网络审计测试先验证外部 DNS 和外部地址会被阻止，再运行整轮及其 CLI 子进程：通过，演练外部网络访问尝试为 0。它不是操作系统级断网隔离，不覆盖任意第三方原生程序。

导出包另在全新临时目录解压，逐文件验证 SHA256，并重新运行网络受限整轮演练。该验证只使用压缩包中的源码和本机 Python，不依赖工作目录配置。

## 验证范围

未验证真实比赛接口、裁判 SLA、轮次过期和 Linux ELF 调试环境。上一轮已验证 C 练习在本机编译、普通输入及修复版超长输入拒绝；macOS 编译结果不代表 Linux ELF 或不同架构上的表现。当前包不含 Linux 虚拟机与系统工具安装介质。

# Code 启动器 · macOS

从「终端」启动本机 Claude Code，并可为单次会话指定 HTTP/HTTPS CONNECT 代理。支持 macOS 14+、Apple 芯片和 Intel。

- **使用当前网络**沿用终端的网络设置。
- **使用专用出口**核对预期 IPv4，通过后手动确认。复查失败或主动断开时，关闭本机代理管理的连接，保留终端。
- **录屏隐藏**默认收起代理地址和凭据，遮住界面中 IPv4 的中间两段。点眼睛可以查看或编辑设置。

[执行文档](执行文档.md)包括直连和中转的接法、给 AI 的配置说明、使用流程、验收与排查。

从源码构建使用 `./tools/build_portable.sh`。需要 macOS、Xcode 命令行工具和 Python 3。构建产物使用本地临时签名。它适用于遵循代理设置的 HTTPS 请求，浏览器和外部工具按各自的网络配置运行。这个独立工具与 Anthropic 无隶属关系，Claude Code 请通过官方渠道安装。

许可证见 [MIT License](LICENSE)。

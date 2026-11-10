import AppKit
import Darwin
import Foundation
import Security

enum LauncherSupport {
    static let home = FileManager.default.homeDirectoryForCurrentUser
    private static let manager = FileManager.default

    static func hideIPv4(in text: String) -> String {
        text.replacingOccurrences(
            of: #"(?<![0-9.])([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}\.([0-9]{1,3})(?![0-9.])"#,
            with: "$1.•••.•••.$2", options: .regularExpression
        )
    }

    static func isIPv4(_ text: String) -> Bool {
        var address = in_addr()
        return text.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    static func binaryDirectories() -> [String] {
        let paths = [".local/bin", ".volta/bin", ".npm-global/bin", ".bun/bin", ".asdf/shims", ".local/share/mise/shims"]
        let nvm = home.appendingPathComponent(".nvm/versions/node", isDirectory: true)
        let versions = ((try? manager.contentsOfDirectory(atPath: nvm.path)) ?? []).sorted { $0.compare($1, options: .numeric) == .orderedDescending }
        var directories = paths.map { home.appendingPathComponent($0).path }
        directories += ["/opt/homebrew/bin", "/usr/local/bin"]
        directories += versions.map { nvm.appendingPathComponent($0).appendingPathComponent("bin").path }
        let environmentPath = ProcessInfo.processInfo.environment["PATH"] ?? ""
        directories += environmentPath.split(separator: ":").filter { $0.hasPrefix("/") }.map(String.init)
        return directories + ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    }

    static func detectCLI() -> String {
        binaryDirectories().map { $0 + "/claude" }.first { isExecutable($0) } ?? ""
    }

    static func isExecutable(_ path: String) -> Bool {
        guard path.hasPrefix("/"), !path.contains("\n"),
              (try? URL(fileURLWithPath: path).resolvingSymlinksInPath().resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else { return false }
        return manager.isExecutableFile(atPath: path)
    }

    static func version(_ path: String) throws -> String {
        guard isExecutable(path) else { throw LauncherError.message("找不到可执行的 Claude Code，请重新选择。") }
        var env = ProcessInfo.processInfo.environment.filter { key, _ in
            !key.hasPrefix("ANTHROPIC_") && !key.hasPrefix("CLAUDE_CODE_OAUTH") && !key.hasPrefix("DYLD_")
        }
        env["PATH"] = ([URL(fileURLWithPath: path).deletingLastPathComponent().path] + binaryDirectories()).joined(separator: ":")
        env["DISABLE_AUTOUPDATER"] = "1"
        for (key, value) in proxyEnvironment("http://127.0.0.1:1") { env[key] = value }
        let output = try command(path, ["--version"], environment: env, timeout: 6)
        guard let value = output.components(separatedBy: .newlines).first(where: { $0.contains("(Claude Code)") }),
              value.range(of: #"^[0-9]+\.[0-9]+\.[0-9]+"#, options: .regularExpression) != nil else {
            throw LauncherError.message("选中的程序没有返回 Claude Code 版本，请重新选择。")
        }
        return value
    }

    static func proxyEnvironment(_ url: String) -> [String: String] {
        var values = ["NO_PROXY": "", "no_proxy": ""]
        for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            values[name] = url
            values[name.lowercased()] = url
        }
        return values
    }

    static func measure(_ local: LocalProxy, expected: String, checkAPI: Bool) throws -> Date {
        let trace = try probe(local, "https://www.cloudflare.com/cdn-cgi/trace?check=" + UUID().uuidString)
        try verifyExit(body: trace.body, http: trace.http, expected: expected)
        let verified = Date()
        if checkAPI {
            let result = try probe(local, "https://api.anthropic.com/")
            guard [200, 401, 404].contains(result.http) else {
                throw LauncherError.message("Claude API 连通检查未通过（HTTP \(result.http)）。")
            }
        }
        return verified
    }

    static func verifyExit(body: String, http: Int, expected: String) throws {
        let measurements = body.components(separatedBy: .newlines).filter { $0.hasPrefix("ip=") }
        guard http == 200, measurements.count == 1, let measurement = measurements.first else {
            throw LauncherError.message("专用通道没有返回可核对的出口。")
        }
        let actual = String(measurement.dropFirst(3))
        guard expected == actual else {
            guard isIPv4(actual) else {
                throw LauncherError.message("实测未得到可核对的 IPv4 出口。")
            }
            throw LauncherError.message("实测出口 \(actual) 与预期 \(expected) 不符。")
        }
    }

    private static func probe(_ local: LocalProxy, _ url: String) throws -> (body: String, http: Int) {
        let config = Data(("proxy = \"" + local.url(probe: true) + "\"\n").utf8)
        let output: String
        do {
            output = try command("/usr/bin/curl", ["-q", "--config", "-", "--noproxy", "", "--silent",
                "--connect-timeout", "6", "--max-time", "10", "--max-filesize", "8192",
                "--proto", "=https", "--write-out", "\n%{http_connect} %{http_code}", url],
                environment: ["PATH": "/usr/bin:/bin"], input: config, timeout: 11)
        } catch { throw LauncherError.message("无法通过专用通道完成检查，请核对代理地址、凭据和线路。") }
        guard let newline = output.lastIndex(of: "\n") else { throw LauncherError.message("专用检查结果无效。") }
        let code = output[output.index(after: newline)...].split(separator: " ")
        guard code.count == 2, code[0] == "200", let http = Int(code[1]) else {
            throw LauncherError.message("专用代理没有建立 HTTPS 连接。")
        }
        return (String(output[..<newline]), http)
    }

    private static func command(_ path: String, _ arguments: [String], environment: [String: String],
                                input: Data? = nil, timeout: TimeInterval) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = environment
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let inputPipe = Pipe()
        process.standardInput = input == nil ? FileHandle.nullDevice : inputPipe
        try process.run()
        let timeoutTask = DispatchWorkItem { [weak process] in
            guard let process, process.isRunning else { return }
            process.terminate()
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { [weak process] in
                if let process, process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timeoutTask)
        defer { timeoutTask.cancel() }
        if let input {
            try inputPipe.fileHandleForWriting.write(contentsOf: input)
            try inputPipe.fileHandleForWriting.close()
        }
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw LauncherError.message("检查程序执行失败。") }
        return String(decoding: bytes, as: UTF8.self)
    }

    static func terminalScript(path: String, project: String, proxy: LocalProxy?) throws -> URL {
        guard isExecutable(path), project.hasPrefix("/"),
              (try? URL(fileURLWithPath: project).resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
            throw LauncherError.message("Claude Code 或项目文件夹已移动，请重新选择。")
        }
        let folder = manager.temporaryDirectory.appendingPathComponent("CodeLauncher-" + UUID().uuidString, isDirectory: true)
        try manager.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let script = folder.appendingPathComponent("启动 Claude Code.command")
        var lines = ["#!/bin/zsh", "/bin/rm -f -- \"$0\"", "/bin/rmdir -- " + quote(folder.path),
                     "cd -- " + quote(project) + " || exit 1"]
        let paths = [URL(fileURLWithPath: path).deletingLastPathComponent().path] + binaryDirectories()
        lines.append("export PATH=" + quote(paths.joined(separator: ":")) + ":$PATH")
        if let proxy {
            for (key, value) in proxyEnvironment(proxy.url(probe: false)).sorted(by: { $0.key < $1.key }) {
                lines.append("export " + key + "=" + quote(value))
            }
        }
        lines.append("exec " + quote(path))
        do {
            try (lines.joined(separator: "\n") + "\n").write(to: script, atomically: true, encoding: .utf8)
            try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
            return script
        } catch {
            try? manager.removeItem(at: folder)
            throw error
        }
    }

    static func quote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

enum PasswordStore {
    private static let account = "active-http-proxy"
    private static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "local.code-launcher.mac",
        kSecAttrAccount as String: account
    ]

    static func read() -> String {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &value) == errSecSuccess,
              let data = value as? Data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    static func save(_ password: String?) throws {
        let status: OSStatus
        if let password {
            let data = Data(password.utf8)
            let updated = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if updated == errSecItemNotFound {
                var entry = query
                entry[kSecValueData as String] = data
                status = SecItemAdd(entry as CFDictionary, nil)
            } else { status = updated }
        } else {
            status = SecItemDelete(query as CFDictionary)
        }
        guard status == errSecSuccess || (password == nil && status == errSecItemNotFound) else {
            throw LauncherError.message("无法更新钥匙串，设置未保存。")
        }
    }
}

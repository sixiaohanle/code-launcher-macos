import AppKit
import SwiftUI

private struct LaunchSettings: Equatable {
    let executable: String
    let project: String
    let proxy: ProxyProfile?
}

private struct CheckedLaunch {
    let settings: LaunchSettings
    let date: Date
    let id = UUID()
}

@MainActor
final class LauncherModel: ObservableObject {
    @Published var executable = ""
    @Published var project = ""
    @Published var dedicated = false
    @Published var address = ""
    @Published var expectedIP = ""
    @Published var username = ""
    @Published var password = ""
    @Published var rememberPassword = false
    @Published private(set) var status = "选择网络模式并检查。"
    @Published private(set) var busy = false
    @Published private(set) var connected = false
    @Published private(set) var hasProtectedTerminal = false
    @Published private var checked: CheckedLaunch?

    private let preferences = UserDefaults.standard
    private var gate: ProxyGate?
    private var local: LocalProxy?
    private var gateProfile: ProxyProfile?
    private var terminalSettings: LaunchSettings?
    private var monitor: Task<Void, Never>?

    var canConfirm: Bool { checked != nil && !busy }
    var hasGate: Bool { gate != nil }

    init() {
        executable = preferences.string(forKey: "executable") ?? ""
        if !LauncherSupport.isExecutable(executable) { executable = LauncherSupport.detectCLI() }
        project = preferences.string(forKey: "project") ?? LauncherSupport.home.path
        dedicated = preferences.bool(forKey: "dedicated")
        address = preferences.string(forKey: "address") ?? ""
        expectedIP = preferences.string(forKey: "expectedIP") ?? ""
        username = preferences.string(forKey: "username") ?? ""
        rememberPassword = preferences.bool(forKey: "rememberPassword")
        if rememberPassword { password = PasswordStore.read() }
    }

    func detect() {
        let result = LauncherSupport.detectCLI()
        if !result.isEmpty { executable = result }
        status = result.isEmpty ? "常见位置未找到 Claude Code。可以手动选择，或打开官方安装说明。" : "已找到 Claude Code，点击检查核验版本。"
    }

    func choose(folder: Bool) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = folder
        panel.canChooseFiles = !folder
        panel.showsHiddenFiles = !folder
        panel.allowsMultipleSelection = false
        panel.prompt = "选择"
        if panel.runModal() == .OK, let url = panel.url {
            if folder { project = url.path } else { executable = url.path }
        }
    }

    private func settings() throws -> LaunchSettings {
        guard LauncherSupport.isExecutable(executable) else {
            throw LauncherError.message("请先安装 Claude Code，或选择本机的 claude 可执行文件。")
        }
        guard project.hasPrefix("/"), (try? URL(fileURLWithPath: project).resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else {
            throw LauncherError.message("请选一个有效的项目文件夹。")
        }
        let proxy = dedicated ? try ProxyProfile(address: address, expectedIP: expectedIP, username: username, password: password) : nil
        return LaunchSettings(executable: executable, project: project, proxy: proxy)
    }

    func save() {
        do {
            let current = try settings()
            try PasswordStore.save(rememberPassword && current.proxy != nil && !password.isEmpty ? password : nil)
            preferences.set(executable, forKey: "executable")
            preferences.set(project, forKey: "project")
            preferences.set(dedicated, forKey: "dedicated")
            // Store only parsed endpoint details. URLs containing credentials are refused above.
            var endpoint: String?
            if let profile = current.proxy {
                var parts = URLComponents()
                parts.scheme = profile.tls ? "https" : "http"
                parts.host = profile.host
                parts.port = Int(profile.port)
                endpoint = parts.string
            }
            preferences.set(endpoint, forKey: "address")
            preferences.set(current.proxy?.expectedIP, forKey: "expectedIP")
            preferences.set(current.proxy?.username, forKey: "username")
            preferences.set(rememberPassword && endpoint != nil, forKey: "rememberPassword")
            status = "设置已保存。"
        } catch { status = error.localizedDescription }
    }

    func check() {
        guard !busy, !connected else { return }
        checked = nil
        do {
            let current = try settings()
            if let terminalSettings, current != terminalSettings {
                throw LauncherError.message("请先结束旧的专用会话，再更换线路或项目。")
            }
            busy = true
            status = "正在核对 Claude Code 安装…"
            Task {
                do {
                    let version = try await Task.detached { try LauncherSupport.version(current.executable) }.value
                    if let profile = current.proxy {
                        status = "正在通过专用线路测量出口 IP…"
                        let local = try await localProxy(for: profile)
                        _ = try await Task.detached {
                            try LauncherSupport.measure(local, expected: profile.expectedIP, checkAPI: true)
                        }.value
                    }
                    let receipt = CheckedLaunch(settings: current, date: Date())
                    checked = receipt
                    status = current.proxy.map { "\(version) · 实测出口 \($0.expectedIP)。等待手动确认。" }
                        ?? "\(version) · 使用当前网络。等待手动确认。"
                    Task {
                        try? await Task.sleep(for: .seconds(60))
                        guard checked?.id == receipt.id else { return }
                        checked = nil
                        status = "检查已过期，请重新检查。"
                    }
                } catch { status = error.localizedDescription }
                busy = false
            }
        } catch { status = error.localizedDescription }
    }

    private func localProxy(for profile: ProxyProfile) async throws -> LocalProxy {
        if gateProfile == profile, let local { return local }
        releaseGate()
        let candidate = ProxyGate(profile: profile) { [weak self] in
            Task { @MainActor in
                guard let self, self.connected else { return }
                self.disconnect(message: "出口验证已过期。专用通道已阻断，终端保留。")
            }
        }
        do {
            let endpoint = try await withCheckedThrowingContinuation { continuation in
                candidate.start { continuation.resume(with: $0) }
            }
            gate = candidate
            local = endpoint
            gateProfile = profile
            return endpoint
        } catch {
            candidate.stop()
            throw error
        }
    }

    func confirm() {
        guard !busy, let receipt = checked else { return }
        checked = nil
        do {
            let current = try settings()
            guard current == receipt.settings, (0..<60).contains(Date().timeIntervalSince(receipt.date)) else {
                throw LauncherError.message("设置已变更或结果已过期，请重新检查。")
            }
            busy = true
            status = "正在确认本次启动…"
            Task {
                do {
                    if let profile = current.proxy {
                        guard let gate, let local else { throw LauncherError.message("专用通道已关闭，请重新检查。") }
                        let proof = try await Task.detached {
                            try LauncherSupport.measure(local, expected: profile.expectedIP, checkAPI: false)
                        }.value
                        gate.authorize(at: proof)
                        connected = true
                        if !hasProtectedTerminal {
                            try await openTerminal(current, local: local)
                            terminalSettings = current
                            hasProtectedTerminal = true
                        }
                        startMonitor(local: local, profile: profile)
                        status = "专用通道已放行 · \(profile.expectedIP)。使用期间请保持入口打开。"
                    } else {
                        try await openTerminal(current, local: nil)
                        status = "已在终端启动 Claude Code，使用当前网络。"
                    }
                } catch {
                    gate?.block()
                    connected = false
                    status = error.localizedDescription
                }
                busy = false
            }
        } catch { status = error.localizedDescription }
    }

    private func openTerminal(_ settings: LaunchSettings, local: LocalProxy?) async throws {
        guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else {
            throw LauncherError.message("找不到 macOS 的终端应用。")
        }
        let script = try LauncherSupport.terminalScript(path: settings.executable, project: settings.project, proxy: local)
        let config = NSWorkspace.OpenConfiguration()
        do {
            _ = try await NSWorkspace.shared.open([script], withApplicationAt: terminal, configuration: config)
        } catch {
            try? FileManager.default.removeItem(at: script.deletingLastPathComponent())
            throw LauncherError.message("未能在终端打开 Claude Code。")
        }
    }

    private func startMonitor(local: LocalProxy, profile: ProxyProfile) {
        monitor?.cancel()
        monitor = Task {
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(12))
                    let proof = try await Task.detached {
                        try LauncherSupport.measure(local, expected: profile.expectedIP, checkAPI: false)
                    }.value
                    guard !Task.isCancelled, connected else { return }
                    gate?.authorize(at: proof)
                } catch {
                    if !Task.isCancelled {
                        disconnect(message: error.localizedDescription + " 专用通道已阻断，终端保留。")
                    }
                    return
                }
            }
        }
    }

    func disconnect(message: String = "专用通道已断开，终端保留。重新检查并确认后可恢复。") {
        checked = nil
        monitor?.cancel()
        monitor = nil
        gate?.block()
        connected = false
        status = message
    }

    func endSession() {
        disconnect(message: "专用会话已结束。旧终端已断开专用代理，可以更换设置。")
        releaseGate()
        terminalSettings = nil
        hasProtectedTerminal = false
    }

    private func releaseGate() {
        gate?.stop()
        gate = nil
        local = nil
        gateProfile = nil
    }
}

private struct LauncherView: View {
    @StateObject private var model = LauncherModel()
    @Environment(\.openURL) private var openURL
    @State private var showEndSession = false
    @State private var showNetworkDetails = false

    private var statusText: String {
        showNetworkDetails ? model.status : LauncherSupport.hideIPv4(in: model.status)
    }

    private var hiddenExitText: String {
        let ip = model.expectedIP.trimmingCharacters(in: .whitespacesAndNewlines)
        if ip.isEmpty { return "未设置" }
        return LauncherSupport.isIPv4(ip) ? LauncherSupport.hideIPv4(in: ip) : "待核对"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Code 启动器").font(.system(size: 24, weight: .semibold))
            Text("从这个入口启动本机 Claude Code。").foregroundStyle(.secondary)

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Claude Code").font(.headline)
                    HStack {
                        TextField("claude 可执行文件路径", text: $model.executable)
                        Button("自动识别", action: model.detect)
                        Button("选择…") { model.choose(folder: false) }
                    }
                    HStack {
                        TextField("项目文件夹", text: $model.project)
                        Button("选择项目…") { model.choose(folder: true) }
                    }
                    Button("打开 Claude Code 官方安装说明") {
                        openURL(URL(string: "https://code.claude.com/docs/en/setup#install-claude-code")!)
                    }.buttonStyle(.link)
                }.padding(8)
            }.disabled(model.busy || model.hasProtectedTerminal)

            GroupBox {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("网络模式", selection: $model.dedicated) {
                        Text("使用当前网络").tag(false)
                        Text("使用专用出口").tag(true)
                    }.pickerStyle(.segmented).disabled(model.busy || model.hasProtectedTerminal)
                    if model.dedicated {
                        HStack {
                            Text("专用线路设置").font(.headline)
                            Spacer()
                            let label = showNetworkDetails ? "隐藏线路详情" : "显示线路详情"
                            Button {
                                showNetworkDetails.toggle()
                            } label: {
                                Image(systemName: showNetworkDetails ? "eye.slash" : "eye")
                            }
                            .help(label)
                            .accessibilityLabel(label)
                        }
                        if showNetworkDetails {
                            VStack(alignment: .leading, spacing: 10) {
                                TextField("代理地址，例如 https://proxy.example.com:443", text: $model.address)
                                TextField("预期 IPv4 出口", text: $model.expectedIP)
                                HStack {
                                    TextField("代理账号（可选）", text: $model.username)
                                    SecureField("代理密码（可选）", text: $model.password)
                                }
                                Toggle("在本机钥匙串记住代理密码", isOn: $model.rememberPassword)
                            }.disabled(model.busy || model.hasProtectedTerminal)
                        } else {
                            Text("预期出口  \(hiddenExitText)").monospacedDigit()
                            Text("点击眼睛查看或编辑线路。").font(.caption).foregroundStyle(.secondary)
                        }
                        Text("专用线路只保护遵循代理设置的 HTTPS 连接。登录前请单独配置浏览器代理，并在该浏览器中核对出口，详见执行文档。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(8)
            }

            Text(statusText).frame(maxWidth: .infinity, minHeight: 40, alignment: .leading)
                .textSelection(.enabled).accessibilityLabel(statusText)
            HStack {
                Button("保存设置", action: model.save).disabled(model.busy || model.hasProtectedTerminal)
                Spacer()
                if model.hasProtectedTerminal {
                    Button("结束专用会话…") { showEndSession = true }.disabled(model.busy)
                }
                if model.connected {
                    Button("断开通道") { model.disconnect() }.disabled(model.busy)
                } else {
                    Button("检查", action: model.check).disabled(model.busy)
                    Button(model.hasProtectedTerminal ? "确认恢复" : "确认启动", action: model.confirm)
                        .buttonStyle(.borderedProminent).disabled(!model.canConfirm)
                }
            }
        }
        .padding(22)
        .frame(minWidth: 625)
        .alert("结束专用会话？", isPresented: $showEndSession) {
            Button("取消", role: .cancel) {}
            Button("结束会话", role: .destructive, action: model.endSession)
        } message: {
            Text("旧终端仍会保留。它的专用代理地址将停用。")
        }
    }
}

final class LauncherDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct CodeLauncher: App {
    @NSApplicationDelegateAdaptor(LauncherDelegate.self) private var delegate

    var body: some Scene {
        Window("Code 启动器", id: "launcher") { LauncherView() }
            .windowResizability(.contentSize)
    }
}

import Foundation

@main
struct PortableSmoke {
    static func main() throws {
        if CommandLine.arguments.count == 2 {
            try serve(port: CommandLine.arguments[1])
            return
        }
        let profile = try ProxyProfile(address: "https://proxy.example:443", expectedIP: "203.0.113.9", username: "user", password: "pass")
        precondition(LauncherSupport.hideIPv4(in: "203.0.113.9 / 198.51.100.20") == "203.•••.•••.9 / 198.•••.•••.20")
        do {
            try LauncherSupport.verifyExit(body: "ip=2001:db8::10\n", http: 200, expected: profile.expectedIP)
            preconditionFailure("An IPv6 exit must fail an IPv4 check")
        } catch {
            precondition(!error.localizedDescription.contains("2001:db8::10"))
        }
        precondition(profile.tls && profile.authorization == "Basic dXNlcjpwYXNz")
        precondition((try? ProxyProfile(address: "http://user:pass@proxy.example:8080", expectedIP: "203.0.113.9", username: "", password: "")) == nil)
        precondition((try? ProxyProfile(address: "http://proxy.example:8080", expectedIP: "not-an-ip", username: "", password: "")) == nil)
        try LauncherSupport.verifyExit(body: "ip=203.0.113.9\n", http: 200, expected: profile.expectedIP)
        for body in ["ip=203.0.113.10\n", "ip=203.0.113.90\n", "", "ip=203.0.113.9\nip=203.0.113.10"] {
            precondition((try? LauncherSupport.verifyExit(body: body, http: 200, expected: profile.expectedIP)) == nil)
        }
        precondition((try? LauncherSupport.verifyExit(body: "ip=203.0.113.9\n", http: 403, expected: profile.expectedIP)) == nil)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("launcher test '" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fake = directory.appendingPathComponent("mock claude")
        let code = """
        #!/bin/zsh
        if [[ "$1" == "--version" ]]; then
            print '2.1.1 (Claude Code)'
        else
            printf '%s\\n%s\\n%s\\n' "$PWD" "$https_proxy" "$NO_PROXY"
        fi
        """
        try code.write(to: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
        let version = try LauncherSupport.version(fake.path)
        precondition(version == "2.1.1 (Claude Code)")
        let proxy = LocalProxy(port: 12345, probeKey: "probe-token", sessionKey: "session-token")
        let script = try LauncherSupport.terminalScript(path: fake.path, project: directory.path, proxy: proxy)
        let result = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = [script.path]
        process.standardOutput = result
        try process.run()
        let output = String(decoding: result.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        precondition(process.terminationStatus == 0)
        precondition(output.contains(directory.lastPathComponent + "\n" + proxy.url(probe: false) + "\n\n"))
        precondition(!FileManager.default.fileExists(atPath: script.path))
        print("Offline profile, IP and launch-script checks passed")
    }

    static func serve(port: String) throws {
        let profile = try ProxyProfile(address: "http://127.0.0.1:" + port, expectedIP: "203.0.113.9", username: "user", password: "pass")
        let gate = ProxyGate(profile: profile) {}
        gate.start { result in
            guard case .success(let endpoint) = result else {
                print("error:", result)
                fflush(stdout)
                exit(1)
            }
            print(endpoint.port, endpoint.probeKey, endpoint.sessionKey)
            fflush(stdout)
            DispatchQueue.global().async {
                while let line = readLine() {
                    switch line {
                    case "enable": gate.authorize(at: Date())
                    case "expired": gate.authorize(at: Date(timeIntervalSinceNow: -31))
                    case "block": gate.block()
                    default: gate.stop(); exit(0)
                    }
                    print("ok")
                    fflush(stdout)
                }
                gate.stop()
                exit(0)
            }
        }
        dispatchMain()
    }
}

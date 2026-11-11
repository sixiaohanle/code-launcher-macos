import Darwin
import Foundation
import Network

enum LauncherError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self { case .message(let text): return text }
    }
}

struct ProxyProfile: Equatable {
    let host: String
    let port: UInt16
    let tls: Bool
    let expectedIP: String
    let username: String
    let password: String

    init(address: String, expectedIP: String, username: String, password: String) throws {
        let ip = expectedIP.trimmingCharacters(in: .whitespacesAndNewlines)
        guard LauncherSupport.isIPv4(ip) else {
            throw LauncherError.message("请填写完整的预期 IPv4 出口。")
        }
        let parts = URLComponents(string: address.trimmingCharacters(in: .whitespacesAndNewlines))
        guard let parts, let scheme = parts.scheme?.lowercased(), ["http", "https"].contains(scheme),
              let host = parts.host, !host.isEmpty,
              let port = parts.port, let number = UInt16(exactly: port), number > 0,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/" else {
            throw LauncherError.message("请输入 HTTP 或 HTTPS 代理地址，包含端口。账号和密码请分开填写。")
        }
        guard !username.contains(":"), !username.isEmpty || password.isEmpty else {
            throw LauncherError.message("代理账号格式不正确。")
        }
        self.host = host
        self.port = number
        self.tls = scheme == "https"
        self.expectedIP = ip
        self.username = username
        self.password = password
    }

    var authorization: String? {
        guard !username.isEmpty else { return nil }
        return "Basic " + Data("\(username):\(password)".utf8).base64EncodedString()
    }
}

struct LocalProxy {
    let port: UInt16
    let probeKey: String
    let sessionKey: String

    func url(probe: Bool) -> String {
        "http://\(probe ? "probe" : "session"):\(probe ? probeKey : sessionKey)@127.0.0.1:\(port)"
    }
}

enum ResidentialTarget {
    static func allows(_ hostname: String) -> Bool {
        let host = hostname.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        var address = in_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 {
            // Darwin accepts leading-zero octets. Upstream resolvers may treat
            // those as octal, so accept only the unambiguous dotted form.
            let octets = host.split(separator: ".")
            guard octets.count == 4, octets.allSatisfy({ $0 == "0" || !$0.hasPrefix("0") }) else { return false }
            let value = UInt32(bigEndian: address.s_addr)
            // These two IANA protocol-assignment addresses are publicly reachable.
            if value == 0xC0000009 || value == 0xC000000A { return true }
            let excluded: [(network: UInt32, mask: UInt32)] = [
                (0x00000000, 0xFF000000), // 0.0.0.0/8, this network
                (0x0A000000, 0xFF000000), // 10.0.0.0/8, private
                (0x64400000, 0xFFC00000), // 100.64.0.0/10, shared address space
                (0x7F000000, 0xFF000000), // 127.0.0.0/8, loopback
                (0xA9FE0000, 0xFFFF0000), // 169.254.0.0/16, link-local
                (0xAC100000, 0xFFF00000), // 172.16.0.0/12, private
                (0xC0000000, 0xFFFFFF00), // 192.0.0.0/24, protocol assignments
                (0xC0000200, 0xFFFFFF00), // 192.0.2.0/24, documentation
                (0xC0A80000, 0xFFFF0000), // 192.168.0.0/16, private
                (0xC6120000, 0xFFFE0000), // 198.18.0.0/15, benchmarks
                (0xC6336400, 0xFFFFFF00), // 198.51.100.0/24, documentation
                (0xCB007100, 0xFFFFFF00), // 203.0.113.0/24, documentation
                (0xE0000000, 0xE0000000), // 224.0.0.0/3, multicast and reserved
            ]
            return !excluded.contains { value & $0.mask == $0.network }
        }
        let localNames = ["local", "lan", "localhost", "localdomain", "home.arpa"]
        guard !localNames.contains(where: { host == $0 || host.hasSuffix("." + $0) }) else { return false }
        // Requiring a multi-label DNS name with an alphabetic TLD also rejects
        // single-label device names, IPv6 and non-canonical numeric IP forms.
        return host.range(
            of: #"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"#,
            options: .regularExpression
        ) != nil
    }
}

final class ProxyGate {
    private let queue = DispatchQueue(label: "local.code-launcher.proxy")
    private let profile: ProxyProfile
    private var listener: NWListener?
    private var tunnels: [UUID: Tunnel] = [:]
    private let probeKey = UUID().uuidString
    private let sessionKey = UUID().uuidString
    private var proof: Date?
    private var expiry: DispatchWorkItem?
    private var stopped = false
    private var ready: ((Result<LocalProxy, Error>) -> Void)?
    private let onBlock: () -> Void

    init(profile: ProxyProfile, onBlock: @escaping () -> Void) {
        self.profile = profile
        self.onBlock = onBlock
    }

    func start(_ completion: @escaping (Result<LocalProxy, Error>) -> Void) {
        queue.async {
            guard !self.stopped else { return }
            self.ready = completion
            do {
                let parameters = NWParameters.tcp
                parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
                let listener = try NWListener(using: parameters)
                self.listener = listener
                listener.stateUpdateHandler = { [weak self, weak listener] state in
                    guard let self, !self.stopped else { return }
                    switch state {
                    case .ready:
                        if let port = listener?.port?.rawValue {
                            self.finishStart(.success(LocalProxy(port: port, probeKey: self.probeKey, sessionKey: self.sessionKey)))
                        }
                    case .failed, .cancelled:
                        self.finishStart(.failure(LauncherError.message("本机专用代理无法监听。")))
                        self.closeApplicationTraffic()
                    default: break
                    }
                }
                listener.newConnectionHandler = { [weak self] client in self?.accept(client) }
                listener.start(queue: self.queue)
                self.queue.asyncAfter(deadline: .now() + 5) { [weak self] in
                    self?.finishStart(.failure(LauncherError.message("本机专用代理启动超时。")))
                }
            } catch { self.finishStart(.failure(error)) }
        }
    }

    private func finishStart(_ result: Result<LocalProxy, Error>) {
        guard let ready else { return }
        self.ready = nil
        DispatchQueue.main.async { ready(result) }
    }

    func authorize(at date: Date) {
        queue.sync {
            let age = Date().timeIntervalSince(date)
            guard !stopped, (0..<30).contains(age) else {
                closeApplicationTraffic()
                return
            }
            proof = date
            expiry?.cancel()
            let item = DispatchWorkItem { [weak self] in self?.closeApplicationTraffic() }
            expiry = item
            queue.asyncAfter(deadline: .now() + (30 - age), execute: item)
        }
    }

    func block() {
        queue.sync { closeApplicationTraffic(notify: false) }
    }

    func stop() {
        queue.sync {
            stopped = true
            ready = nil
            closeApplicationTraffic(notify: false)
            listener?.cancel()
            listener = nil
            Array(tunnels.values).forEach { $0.close() }
        }
    }

    private func closeApplicationTraffic(notify: Bool = true) {
        let wasOpen = proof != nil
        proof = nil
        expiry?.cancel()
        expiry = nil
        Array(tunnels.values).filter { !$0.isProbe }.forEach { $0.close() }
        if notify && wasOpen { DispatchQueue.main.async(execute: onBlock) }
    }

    private func accept(_ client: NWConnection) {
        guard !stopped, tunnels.count < 64 else { client.cancel(); return }
        let id = UUID()
        let tunnel = Tunnel(client: client, profile: profile, queue: queue) { [weak self] in
            self?.tunnels.removeValue(forKey: id)
        }
        tunnels[id] = tunnel
        tunnel.start { [weak self] auth in
            guard let self else { return nil }
            let probe = "Basic " + Data("probe:\(self.probeKey)".utf8).base64EncodedString()
            if auth == probe { return true }
            let session = "Basic " + Data("session:\(self.sessionKey)".utf8).base64EncodedString()
            guard auth == session, let proof = self.proof, (0..<30).contains(Date().timeIntervalSince(proof)) else { return nil }
            return false
        }
    }
}

private final class Tunnel {
    private let client: NWConnection
    private let profile: ProxyProfile
    private let queue: DispatchQueue
    private let onClose: () -> Void
    private var upstream: NWConnection?
    private var closed = false
    private var established = false
    private var finishedDirections = 0
    private(set) var isProbe = false

    init(client: NWConnection, profile: ProxyProfile, queue: DispatchQueue, onClose: @escaping () -> Void) {
        self.client = client
        self.profile = profile
        self.queue = queue
        self.onClose = onClose
    }

    func start(authorize: @escaping (String) -> Bool?) {
        client.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 12) { [weak self] in
            if self?.established == false { self?.close() }
        }
        readHeader(client) { [weak self] header, rest in
            guard let self else { return }
            let lines = header.components(separatedBy: "\r\n")
            let request = lines[0].split(separator: " ")
            let auth = lines.dropFirst().first { $0.lowercased().hasPrefix("proxy-authorization:") }
                .map { String($0.dropFirst("proxy-authorization:".count)).trimmingCharacters(in: .whitespaces) }
            guard request.count == 3, request[0] == "CONNECT",
                  request[1].range(of: #"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}:443$"#, options: .regularExpression) != nil,
                  request[2] == "HTTP/1.1" || request[2] == "HTTP/1.0" else {
                self.reject("403 Forbidden"); return
            }
            guard let auth, let probe = authorize(auth) else { self.reject("403 Forbidden"); return }
            guard ResidentialTarget.allows(String(request[1].dropLast(4))) else {
                self.reject("403 Local target blocked"); return
            }
            self.isProbe = probe
            self.connect(to: String(request[1]), pending: rest)
        }
    }

    private func connect(to target: String, pending: Data) {
        let parameters: NWParameters
        if profile.tls {
            let tls = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, profile.host)
            parameters = NWParameters(tls: tls)
        } else {
            parameters = .tcp
        }
        guard let port = NWEndpoint.Port(rawValue: profile.port) else { close(); return }
        let remote = NWConnection(host: NWEndpoint.Host(profile.host), port: port, using: parameters)
        upstream = remote
        remote.stateUpdateHandler = { [weak self, weak remote] state in
            guard let self, let remote, !self.closed else { return }
            switch state {
            case .ready:
                remote.stateUpdateHandler = nil
                var request = "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n"
                if let auth = self.profile.authorization { request += "Proxy-Authorization: \(auth)\r\n" }
                remote.send(content: Data((request + "\r\n").utf8), completion: .contentProcessed { [weak self] error in
                    guard let self, !self.closed else { return }
                    guard error == nil else { self.close(); return }
                    self.readHeader(remote) { [weak self] header, response in
                        guard let self else { return }
                        let status = header.components(separatedBy: "\r\n")[0].split(separator: " ")
                        guard status.count >= 2, status[0].hasPrefix("HTTP/1."), status[1] == "200" else {
                            self.reject(status.count >= 2 && status[1] == "407" ? "407 Proxy Authentication Required" : "502 Bad Gateway")
                            return
                        }
                        self.established = true
                        let handshake = Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8) + response
                        self.forward(handshake, from: remote, to: self.client)
                        self.forward(pending, from: self.client, to: remote)
                    }
                })
            case .failed, .cancelled: self.close()
            default: break
            }
        }
        remote.start(queue: queue)
    }

    private func readHeader(_ connection: NWConnection, accumulated: Data = Data(), completion: @escaping (String, Data) -> Void) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            guard error == nil, let data, !data.isEmpty else { self.close(); return }
            let bytes = accumulated + data
            if let delimiter = bytes.range(of: Data([13, 10, 13, 10])),
               delimiter.lowerBound <= 16384,
               let header = String(data: bytes[..<delimiter.lowerBound], encoding: .ascii) {
                completion(header, Data(bytes[delimiter.upperBound...]))
            } else if bytes.count < 16384 && !done {
                self.readHeader(connection, accumulated: bytes, completion: completion)
            } else { self.close() }
        }
    }

    private func forward(_ data: Data, from: NWConnection, to: NWConnection) {
        if data.isEmpty { pump(from, to); return }
        to.send(content: data, completion: .contentProcessed { [weak self] error in
            if error == nil { self?.pump(from, to) } else { self?.close() }
        })
    }

    private func pump(_ from: NWConnection, _ to: NWConnection) {
        guard !closed else { return }
        from.receive(minimumIncompleteLength: 1, maximumLength: 32768) { [weak self] data, _, done, error in
            guard let self, !self.closed else { return }
            guard error == nil else { self.close(); return }
            if done {
                to.send(content: data, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { [weak self] error in
                    guard let self else { return }
                    self.finishedDirections += 1
                    if error != nil || self.finishedDirections == 2 { self.close() }
                })
            } else { self.forward(data ?? Data(), from: from, to: to) }
        }
    }

    private func reject(_ status: String) {
        client.send(content: Data("HTTP/1.1 \(status)\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".utf8),
                    completion: .contentProcessed { [weak self] _ in self?.close() })
    }

    func close() {
        guard !closed else { return }
        closed = true
        client.cancel()
        upstream?.cancel()
        onClose()
    }
}

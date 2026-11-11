"""Exercise the shipped gate only, using an isolated mock CONNECT upstream."""
import base64
import socket
import socketserver
import subprocess
import sys
import threading


class Proxy(socketserver.StreamRequestHandler):
    def handle(self):
        with self.server.arrival_lock:
            self.server.arrivals += 1
        request = self.rfile.readline().rstrip()
        headers = {}
        while line := self.rfile.readline().strip():
            key, value = line.split(b":", 1)
            headers[key.lower()] = value.strip()
        assert request == b"CONNECT test.example:443 HTTP/1.1", request
        assert headers[b"proxy-authorization"] == b"Basic dXNlcjpwYXNz"
        self.wfile.write(b"HTTP/1.1 200 OK\r\n\r\n")
        while data := self.rfile.read1(4096):
            self.wfile.write(data)


def check_gate(binary):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy) as proxy:
        proxy.arrivals = 0
        proxy.arrival_lock = threading.Lock()
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        try:
            with subprocess.Popen([binary, str(proxy.server_address[1])],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as app:
                try:
                    endpoint = app.stdout.readline().split()
                    assert len(endpoint) == 3 and endpoint[0].isdigit(), endpoint
                    port, probe_key, session_key = endpoint

                    def control(command):
                        app.stdin.write(command + "\n")
                        app.stdin.flush()
                        assert app.stdout.readline().strip() == "ok"

                    def open_tunnel(user, key, status, host="test.example"):
                        conn = socket.create_connection(("127.0.0.1", int(port)), timeout=5)
                        try:
                            data = f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n".encode()
                            if key:
                                auth = base64.b64encode(f"{user}:{key}".encode())
                                data += b"Proxy-Authorization: Basic " + auth + b"\r\n"
                            conn.sendall(data + b"\r\n")
                            header = b""
                            while not header.endswith(b"\r\n\r\n"):
                                byte = conn.recv(1)
                                assert byte, (host, header)
                                header += byte
                            assert header.split()[1] == str(status).encode(), (host, header)
                            return conn
                        except BaseException:
                            conn.close()
                            raise

                    with open_tunnel("", "", 403), open_tunnel("session", session_key, 403):
                        pass
                    with open_tunnel("probe", probe_key, 200) as conn:
                        conn.sendall(b"probe-data")
                        assert conn.recv(32) == b"probe-data"
                    control("enable")
                    with proxy.arrival_lock:
                        arrivals = proxy.arrivals
                    for user, key in (("probe", probe_key), ("session", session_key)):
                        for host in ("phone.local", "PHONE.LOCAL.", "phone.lan", "phone.localdomain",
                                     "phone.localhost", "router.home.arpa", "phone", "127.0.0.1",
                                     "192.168.1.1", "10.0.0.1", "100.64.1.1", "127.1",
                                     "0177.0.0.1", "0x7f000001", "198.18.0.1",
                                     "224.0.0.251", "[::1]"):
                            with open_tunnel(user, key, 403, host):
                                pass
                    with proxy.arrival_lock:
                        assert proxy.arrivals == arrivals, "A blocked target opened an upstream socket"
                    with open_tunnel("session", session_key, 200) as conn:
                        conn.sendall(b"session-data")
                        assert conn.recv(32) == b"session-data"
                        control("block")
                        assert conn.recv(32) == b""
                    with open_tunnel("session", session_key, 403):
                        pass
                    control("enable")
                    with open_tunnel("session", session_key, 200) as conn:
                        control("expired")
                        assert conn.recv(32) == b""
                    with open_tunnel("session", session_key, 403):
                        pass
                    print("Loopback gate checks passed")
                finally:
                    app.stdin.close()
                    app.wait(timeout=5)
        finally:
            proxy.shutdown()


if __name__ == "__main__":
    check_gate(sys.argv[1])

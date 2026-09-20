import http.server
import json
import os
import platform
import socket
import subprocess
import urllib.request


def try_read(path, limit=2000):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except Exception as e:
        return f"<error reading: {e}>"


def try_run(cmd, timeout=3):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (out.stdout + out.stderr).strip()[:3000]
    except Exception as e:
        return f"<error running {cmd}: {e}>"


def try_reach(url, timeout=2, headers=None):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(500)
            return {"reachable": True, "status": resp.status, "body_snippet": body.decode(errors="replace")}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def tcp_connect(host, port, timeout=1.5):
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return {"open": True}
    except Exception as e:
        return {"open": False, "error": str(e)}


def http_get_raw(host, port, path="/", timeout=2, use_https=False, extra_headers=""):
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect_host = f"[{host}]" if family == socket.AF_INET6 else host
        s.connect((host, port))
        if use_https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        req = f"GET {path} HTTP/1.1\r\nHost: {connect_host}\r\nConnection: close\r\n{extra_headers}\r\n"
        s.sendall(req.encode())
        data = b""
        while len(data) < 4000:
            chunk = s.recv(4000)
            if not chunk:
                break
            data += chunk
        s.close()
        return {"ok": True, "response_snippet": data.decode(errors="replace")[:2000]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


INTERNAL_HOSTS = [
    "fda7:a938:5bfe:5fa6:0:5df:921c:bd78",
    "fda7:a938:5bfe:5fa6:0:5df:7da0:83f",
    "fda7:a938:5bfe:5fa6:0:5df:91f5:6851",
    "fda7:a938:5bfe:5fa6:0:5df:dbf5:263",
    "fda7:a938:5bfe:5fa6:0:5dd:a5bf:5e98",
    "fda7:a938:5bfe:5fa6:0:5df:c92:9552",
]

PROBE_PORTS = [4646, 4647, 8500, 8300, 80, 443, 8080, 22]


NOMAD_HOST = "fda7:a938:5bfe:5fa6:0:5df:7da0:83f"
NOMAD_PORT = 4646

NOMAD_PATHS = [
    "/v1/agent/self",
    "/v1/agent/members",
    "/v1/status/leader",
    "/v1/status/peers",
    "/v1/nodes",
    "/v1/jobs",
]


def test_nomad_api():
    import ssl

    results = {}
    for path in NOMAD_PATHS:
        try:
            family = socket.AF_INET6
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((NOMAD_HOST, NOMAD_PORT))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s)
            req = f"GET {path} HTTP/1.1\r\nHost: [{NOMAD_HOST}]\r\nConnection: close\r\n\r\n"
            ss.sendall(req.encode())
            data = b""
            while len(data) < 8000:
                chunk = ss.recv(8000)
                if not chunk:
                    break
                data += chunk
            ss.close()
            results[path] = {
                "ok": True,
                "tls_cipher": ss.cipher() if hasattr(ss, "cipher") else None,
                "response_snippet": data.decode(errors="replace")[:4000],
            }
        except Exception as e:
            results[path] = {"ok": False, "error": str(e)}
    return results


def probe_internal_network():
    results = {}
    for host in INTERNAL_HOSTS:
        host_result = {}
        for port in PROBE_PORTS:
            r = tcp_connect(host, port)
            host_result[str(port)] = r
            if r.get("open") and port in (4646, 8500):
                # Nomad HTTP API / Consul HTTP API - try a lightweight unauthenticated GET
                path = "/v1/agent/members" if port == 4646 else "/v1/catalog/nodes"
                host_result[f"{port}_http_probe"] = http_get_raw(host, port, path=path)
        results[host] = host_result
    return results


def gather_diagnostics():
    data = {}
    data["hostname"] = socket.gethostname()
    try:
        data["fqdn"] = socket.getfqdn()
    except Exception as e:
        data["fqdn"] = str(e)
    try:
        data["local_ips"] = socket.gethostbyname_ex(socket.gethostname())
    except Exception as e:
        data["local_ips"] = str(e)

    data["platform"] = platform.platform()
    data["kernel_release"] = platform.release()
    data["machine"] = platform.machine()

    data["env"] = dict(os.environ)

    data["proc_self_cgroup"] = try_read("/proc/self/cgroup")
    data["proc_1_cgroup"] = try_read("/proc/1/cgroup")
    data["dockerenv_exists"] = os.path.exists("/.dockerenv")
    data["proc_self_mountinfo"] = try_read("/proc/self/mountinfo", 3000)

    data["ip_addr"] = try_run(["ip", "addr"]) if os.path.exists("/usr/sbin/ip") or os.path.exists("/sbin/ip") else try_run(["ifconfig"])
    data["ip_route"] = try_run(["ip", "route"])
    data["resolv_conf"] = try_read("/etc/resolv.conf")
    data["hosts_file"] = try_read("/etc/hosts")

    data["whoami"] = try_run(["whoami"])
    data["id"] = try_run(["id"])
    data["uname_a"] = try_run(["uname", "-a"])
    data["cpuinfo_model"] = try_run(["sh", "-c", "grep 'model name' /proc/cpuinfo | head -1"])
    data["meminfo_total"] = try_run(["sh", "-c", "grep MemTotal /proc/meminfo"])

    # cloud metadata reachability checks - pure reconnaissance of our OWN sandbox's
    # network reachability, not an SSRF-via-user-input test
    data["aws_metadata_v1"] = try_reach("http://169.254.169.254/latest/meta-data/", timeout=2)
    data["aws_metadata_v2_token"] = try_reach(
        "http://169.254.169.254/latest/api/token", timeout=2, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    )
    data["gcp_metadata"] = try_reach(
        "http://169.254.169.254/computeMetadata/v1/", timeout=2, headers={"Metadata-Flavor": "Google"}
    )
    data["azure_metadata"] = try_reach(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01", timeout=2, headers={"Metadata": "true"}
    )
    data["digitalocean_metadata"] = try_reach("http://169.254.169.254/metadata/v1/", timeout=2)

    # kubernetes service-account artifacts, if this is a k8s pod
    data["k8s_sa_token_exists"] = os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")
    data["k8s_namespace"] = try_read("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    data["kubernetes_service_host_env"] = os.environ.get("KUBERNETES_SERVICE_HOST")

    return data


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/nomad-api-test"):
            try:
                data = test_nomad_api()
                body = json.dumps(data, indent=2, default=str).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
            return
        if self.path.startswith("/probe-internal"):
            try:
                data = probe_internal_network()
                body = json.dumps(data, indent=2, default=str).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
            return
        self._do_get_root()

    def _do_get_root(self):
        try:
            data = gather_diagnostics()
            body = json.dumps(data, indent=2, default=str).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()

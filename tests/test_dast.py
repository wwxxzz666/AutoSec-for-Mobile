"""DAST 阶段回归测试。"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mobilesec.config import ScanConfig
from mobilesec.stages import dast


class _CorsHandler(BaseHTTPRequestHandler):
    acao = "*"

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if self.acao:
            self.send_header("Access-Control-Allow-Origin", self.acao)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args):
        pass


@pytest.fixture
def cors_server():
    """起一个返回 Access-Control-Allow-Origin 的本地服务。"""
    servers = []

    def _start(acao: str):
        handler = type("H", (_CorsHandler,), {"acao": acao})
        server = HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}"

    yield _start

    for s in servers:
        s.shutdown()
        s.server_close()


def _titles(findings):
    return [f.title for f in findings]


def test_cors_checked_even_without_auth_token(cors_server):
    """没配 auth token 时 CORS 仍必须被检测。

    历史问题：_run_auth_tests 里 `if not token: return findings` 写在
    CORS 检查之前，未配置 AUTH_TOKEN 的项目永远不会被检查 CORS。
    """
    base_url = cors_server("*")

    findings = dast._run_auth_tests(base_url, ScanConfig(), token="")

    assert "CORS 配置过于宽松" in _titles(findings), (
        "未配置 token 时 CORS 检查被跳过了：" + str(_titles(findings))
    )


def test_cors_not_reported_when_restrictive(cors_server):
    base_url = cors_server("https://trusted.example")

    findings = dast._run_auth_tests(base_url, ScanConfig(), token="")

    assert "CORS 配置过于宽松" not in _titles(findings)


def test_unauthenticated_check_still_requires_token(cors_server):
    """无 token 时不应做"未做认证保护"判断（无从对比），但仍做 CORS。"""
    base_url = cors_server("https://trusted.example")

    findings = dast._run_auth_tests(base_url, ScanConfig(), token="")

    assert "API 端点未做认证保护" not in _titles(findings)


def test_unauthenticated_check_reports_when_token_given(cors_server):
    base_url = cors_server("https://trusted.example")

    findings = dast._run_auth_tests(base_url, ScanConfig(), token="some-token")

    assert "API 端点未做认证保护" in _titles(findings)

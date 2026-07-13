import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import janus_compose_ports as ports


class ProtocolInferenceTests(unittest.TestCase):
    def infer(self, source: str, *, label: str = "", container_port: int = 8080):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service = root / "chat"
            service.mkdir()
            (service / "app.py").write_text(source, encoding="utf8")
            labels = ""
            if label:
                labels = f'    labels:\n      - "janus.protocol={label}"\n'
            compose = root / "compose.yml"
            compose.write_text(
                "services:\n"
                "  chat:\n"
                "    build: ./chat\n"
                f"{labels}"
                "    ports:\n"
                f'      - "9000:{container_port}"\n',
                encoding="utf8",
            )
            plan = ports.PortPlan(
                compose=compose,
                line=0,
                service="chat",
                original_mapping=f"9000:{container_port}",
                original_port=9000,
                target_port=11500,
                container_port=container_port,
                already_patched=False,
            )
            return ports.infer_service(plan)

    def test_protocol_choices_include_ws_and_wss(self):
        self.assertIn("ws", ports.PROTOCOLS)
        self.assertIn("wss", ports.PROTOCOLS)
        self.assertIn("wss", ports.TLS_PROTOCOLS)

    def test_detects_cleartext_websocket_server(self):
        inference = self.infer(
            "import websockets\n"
            "server = websockets.serve(handler, '0.0.0.0', 8080)\n"
        )
        self.assertEqual("ws", inference.protocol)
        self.assertFalse(inference.target_tls)
        self.assertTrue(any("WebSocket" in item for item in inference.evidence))

    def test_detects_tls_websocket_server_as_wss(self):
        inference = self.infer(
            "import websockets\n"
            "server = websockets.serve(handler, '0.0.0.0', 8443, ssl=ssl_context)\n",
            container_port=8443,
        )
        self.assertEqual("wss", inference.protocol)
        self.assertTrue(inference.target_tls)

    def test_detects_node_https_websocket_server_as_wss(self):
        inference = self.infer(
            "const https = require('https')\n"
            "const { WebSocketServer } = require('ws')\n"
            "const server = https.createServer(options)\n"
            "const wss = new WebSocketServer({ server })\n",
            container_port=8443,
        )
        self.assertEqual("wss", inference.protocol)
        self.assertTrue(inference.target_tls)

    def test_plain_http_service_stays_http(self):
        inference = self.infer(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.get('/health')\n"
            "def health(): return 'ok'\n"
        )
        self.assertEqual("http", inference.protocol)

    def test_websocket_client_code_does_not_imply_server(self):
        inference = self.infer(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "client_example = 'new WebSocket(\"wss://example.test/socket\")'\n"
        )
        self.assertEqual("http", inference.protocol)

    def test_explicit_ws_listener_does_not_override_backend_tls(self):
        inference = self.infer(
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.run(ssl_context=('cert.pem', 'key.pem'))\n",
            label="ws",
            container_port=8443,
        )
        self.assertEqual("ws", inference.protocol)
        self.assertTrue(inference.target_tls)

    def test_explicit_wss_listener_can_target_cleartext_backend(self):
        inference = self.infer(
            "from flask import Flask\napp = Flask(__name__)\n",
            label="wss",
        )
        self.assertEqual("wss", inference.protocol)
        self.assertFalse(inference.target_tls)

    def test_common_server_framework_hints(self):
        samples = (
            'const wss = new WebSocketServer({ server })',
            'proxy_set_header Upgrade $http_upgrade;',
            '@ServerEndpoint("/events")',
            'class ChatConsumer(AsyncWebsocketConsumer): pass',
            'var upgrader = websocket.Upgrader{}',
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(ports.websocket_evidence(sample))


if __name__ == "__main__":
    unittest.main()

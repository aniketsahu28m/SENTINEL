import base64
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
SCANNER_PATH = BACKEND_DIR / "scanner.py"


def _install_dependency_stubs():
    class _IdentityDecorator:
        def __call__(self, *args, **kwargs):
            if args and callable(args[0]) and len(args) == 1 and not kwargs:
                return args[0]

            def decorator(func):
                return func

            return decorator

    flask_module = types.ModuleType("flask")

    class FakeFlask:
        def __init__(self, name):
            self.name = name
            self.config = {}
            self.secret_key = None

        route = _IdentityDecorator()
        before_request = _IdentityDecorator()
        after_request = _IdentityDecorator()
        teardown_appcontext = _IdentityDecorator()
        errorhandler = _IdentityDecorator()
        context_processor = _IdentityDecorator()

    flask_module.Flask = FakeFlask
    flask_module.g = types.SimpleNamespace()
    flask_module.jsonify = lambda *args, **kwargs: args[0] if args else kwargs
    flask_module.make_response = lambda value=None, *args, **kwargs: value
    flask_module.redirect = lambda location, code=302: location
    flask_module.render_template = lambda *args, **kwargs: ""
    flask_module.request = types.SimpleNamespace(headers={}, cookies={}, args={})
    flask_module.url_for = lambda *args, **kwargs: ""
    flask_module.flash = lambda *args, **kwargs: None
    sys.modules["flask"] = flask_module

    flask_cors_module = types.ModuleType("flask_cors")
    flask_cors_module.CORS = lambda app, *args, **kwargs: app
    sys.modules["flask_cors"] = flask_cors_module

    bcrypt_module = types.ModuleType("bcrypt")
    bcrypt_module.gensalt = lambda: b"salt"
    bcrypt_module.hashpw = lambda password, salt: b"hashed:" + password
    sys.modules["bcrypt"] = bcrypt_module

    gnupg_module = types.ModuleType("gnupg")

    class FakeEncryptedData:
        def __init__(self, payload):
            self.ok = True
            self.status = "ok"
            self._payload = payload

        def __str__(self):
            if isinstance(self._payload, bytes):
                return self._payload.decode("utf-8", errors="ignore")
            return str(self._payload)

    class FakeGPG:
        def encrypt(self, data, recipient):
            return FakeEncryptedData(data)

    gnupg_module.GPG = FakeGPG
    sys.modules["gnupg"] = gnupg_module

    nmap_module = types.ModuleType("nmap")

    class FakePortScanner:
        pass

    nmap_module.PortScanner = FakePortScanner
    sys.modules["nmap"] = nmap_module

    apscheduler_module = types.ModuleType("apscheduler")
    schedulers_module = types.ModuleType("apscheduler.schedulers")
    background_module = types.ModuleType("apscheduler.schedulers.background")

    class FakeBackgroundScheduler:
        def __init__(self, *args, **kwargs):
            pass

    background_module.BackgroundScheduler = FakeBackgroundScheduler
    sys.modules["apscheduler"] = apscheduler_module
    sys.modules["apscheduler.schedulers"] = schedulers_module
    sys.modules["apscheduler.schedulers.background"] = background_module

    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.load_dotenv = lambda *args, **kwargs: None
    sys.modules["dotenv"] = dotenv_module

    cryptography_module = types.ModuleType("cryptography")
    hazmat_module = types.ModuleType("cryptography.hazmat")
    primitives_module = types.ModuleType("cryptography.hazmat.primitives")
    ciphers_module = types.ModuleType("cryptography.hazmat.primitives.ciphers")
    aead_module = types.ModuleType("cryptography.hazmat.primitives.ciphers.aead")

    class FakeAESGCM:
        def __init__(self, key):
            self.key = key

        @staticmethod
        def generate_key(bit_length=256):
            return bytes(range(bit_length // 8))

        def encrypt(self, nonce, plaintext, associated_data):
            return (
                len(nonce).to_bytes(1, byteorder="big")
                + nonce
                + len(associated_data).to_bytes(2, byteorder="big")
                + associated_data
                + plaintext[::-1]
            )

        def decrypt(self, nonce, ciphertext, associated_data):
            nonce_length = ciphertext[0]
            cursor = 1
            if ciphertext[cursor:cursor + nonce_length] != nonce:
                raise ValueError("Nonce mismatch")
            cursor += nonce_length

            ad_length = int.from_bytes(ciphertext[cursor:cursor + 2], byteorder="big")
            cursor += 2
            if ciphertext[cursor:cursor + ad_length] != associated_data:
                raise ValueError("Associated data mismatch")
            cursor += ad_length
            return ciphertext[cursor:][::-1]

    aead_module.AESGCM = FakeAESGCM
    sys.modules["cryptography"] = cryptography_module
    sys.modules["cryptography.hazmat"] = hazmat_module
    sys.modules["cryptography.hazmat.primitives"] = primitives_module
    sys.modules["cryptography.hazmat.primitives.ciphers"] = ciphers_module
    sys.modules["cryptography.hazmat.primitives.ciphers.aead"] = aead_module


def _load_scanner_module(temp_dir: Path):
    data_dir = temp_dir / "data"
    (data_dir / "scans").mkdir(parents=True, exist_ok=True)
    (data_dir / "anomalies").mkdir(parents=True, exist_ok=True)
    (data_dir / "encrypted_reports").mkdir(parents=True, exist_ok=True)

    key = bytes(range(32))
    (data_dir / "users.json").write_text("[]", encoding="utf-8")
    (data_dir / "keys.json").write_text(
        json.dumps({"report_encryption_key": base64.urlsafe_b64encode(key).decode("utf-8")}),
        encoding="utf-8",
    )

    spec = importlib.util.spec_from_file_location("scanner_under_test", SCANNER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScannerHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls._original_cwd = os.getcwd()
        os.chdir(cls._temp_dir.name)
        _install_dependency_stubs()
        cls.scanner = _load_scanner_module(Path(cls._temp_dir.name))

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls._original_cwd)
        cls._temp_dir.cleanup()

    def test_load_users_bootstraps_admin_when_missing(self):
        temp_users_file = Path(self._temp_dir.name) / "bootstrap-users.json"
        original_users_file = self.scanner.USERS_FILE
        self.addCleanup(setattr, self.scanner, "USERS_FILE", original_users_file)
        self.scanner.USERS_FILE = str(temp_users_file)
        os.environ["DEFAULT_ADMIN_PASSWORD"] = "opensesame"
        self.addCleanup(os.environ.pop, "DEFAULT_ADMIN_PASSWORD", None)

        users = self.scanner.load_users()

        self.assertIn("admin", users)
        self.assertEqual(users["admin"]["role"], "admin")
        self.assertEqual(users["admin"]["password_hash"], "hashed:opensesame")
        payload = json.loads(temp_users_file.read_text(encoding="utf-8"))
        self.assertEqual(payload[0]["username"], "admin")

    def test_save_users_persists_expected_schema(self):
        temp_users_file = Path(self._temp_dir.name) / "saved-users.json"
        original_users_file = self.scanner.USERS_FILE
        self.addCleanup(setattr, self.scanner, "USERS_FILE", original_users_file)
        self.scanner.USERS_FILE = str(temp_users_file)

        self.scanner.save_users(
            {
                "alice": {"password_hash": "hash-alice", "role": "admin"},
                "bob": {"password_hash": "hash-bob"},
            }
        )

        payload = json.loads(temp_users_file.read_text(encoding="utf-8"))
        self.assertEqual(
            payload,
            [
                {"username": "alice", "password_hash": "hash-alice", "role": "admin"},
                {"username": "bob", "password_hash": "hash-bob", "role": "user"},
            ],
        )

    def test_encrypt_and_decrypt_report_content_round_trip(self):
        original_key = self.scanner.REPORT_ENCRYPTION_KEY
        self.addCleanup(setattr, self.scanner, "REPORT_ENCRYPTION_KEY", original_key)
        self.scanner.REPORT_ENCRYPTION_KEY = bytes(range(32))

        encrypted = self.scanner.encrypt_report_content("scan payload", b"sentinel-report")
        decrypted = self.scanner.decrypt_report_content(
            encrypted["nonce"], encrypted["ciphertext"], encrypted["associated_data"]
        )

        self.assertEqual(decrypted, "scan payload")
        self.assertEqual(sorted(encrypted.keys()), ["associated_data", "ciphertext", "nonce"])

    def test_resolve_report_path_enforces_safe_filenames(self):
        scans_dir = Path(self._temp_dir.name) / "data" / "scans"
        anomalies_dir = Path(self._temp_dir.name) / "data" / "anomalies"
        scan_file = scans_dir / "demo.json"
        scan_file.write_text("{}", encoding="utf-8")

        original_scans_dir = self.scanner.SCANS_DIR
        original_anomalies_dir = self.scanner.ANOMALIES_DIR
        self.addCleanup(setattr, self.scanner, "SCANS_DIR", original_scans_dir)
        self.addCleanup(setattr, self.scanner, "ANOMALIES_DIR", original_anomalies_dir)
        self.scanner.SCANS_DIR = str(scans_dir)
        self.scanner.ANOMALIES_DIR = str(anomalies_dir)

        resolved = self.scanner._resolve_report_path("scan", "demo.json")

        self.assertEqual(Path(resolved), scan_file)
        with self.assertRaises(ValueError):
            self.scanner._resolve_report_path("scan", "../demo.json")
        with self.assertRaises(ValueError):
            self.scanner._resolve_report_path("other", "demo.json")
        with self.assertRaises(FileNotFoundError):
            self.scanner._resolve_report_path("anomaly", "missing.json")

    def test_session_helpers_prune_and_issue_tokens(self):
        original_sessions = self.scanner.active_sessions
        original_ttl = self.scanner.SESSION_TTL_SECONDS
        self.addCleanup(setattr, self.scanner, "active_sessions", original_sessions)
        self.addCleanup(setattr, self.scanner, "SESSION_TTL_SECONDS", original_ttl)

        self.scanner.active_sessions = {
            "expired": {
                "username": "old",
                "issued_at": datetime.utcnow() - timedelta(seconds=120),
            },
            "valid": {
                "username": "new",
                "issued_at": datetime.utcnow(),
            },
        }
        self.scanner.SESSION_TTL_SECONDS = 60

        token = self.scanner.issue_session_token("alice")
        self.scanner.prune_expired_sessions()

        self.assertNotIn("expired", self.scanner.active_sessions)
        self.assertIn("valid", self.scanner.active_sessions)
        self.assertIn(token, self.scanner.active_sessions)
        self.assertEqual(self.scanner.active_sessions[token]["username"], "alice")


if __name__ == "__main__":
    unittest.main()
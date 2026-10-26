"""Regression checks for the SQLx/RSA dependency audit finding."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DependencyAuditTests(unittest.TestCase):
    def test_backend_lockfile_does_not_reintroduce_sqlx_mysql_rsa(self):
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        package_names = {package["name"] for package in lock["package"]}
        for removed_crypto_package in ("rsa", "openssl", "openssl-sys", "native-tls", "tokio-native-tls"):
            self.assertNotIn(removed_crypto_package, package_names)

        sqlx_packages = [package for package in lock["package"] if package["name"] == "sqlx"]
        self.assertEqual(len(sqlx_packages), 1)
        self.assertEqual(sqlx_packages[0]["version"], "0.9.0")

        manifest = tomllib.loads((ROOT / "backend/Cargo.toml").read_text())
        sqlx = manifest["dependencies"]["sqlx"]
        self.assertFalse(sqlx["default-features"])
        self.assertIn("postgres", sqlx["features"])
        self.assertNotIn("mysql", sqlx["features"])
        self.assertNotIn("mysql-rsa", sqlx["features"])


if __name__ == "__main__":
    unittest.main()

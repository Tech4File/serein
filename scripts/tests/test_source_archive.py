import tempfile
import unittest
from pathlib import Path

from scripts.create_source_archive import ROOT, included


class SourceArchiveSafetyTests(unittest.TestCase):
    def test_excludes_credentials_builds_and_out_of_tree_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            private_names = [".netrc", ".git-credentials", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa"]
            for name in private_names:
                path = base / name
                path.write_text("secret", encoding="utf-8")
                self.assertFalse(included(path, ROOT / "serein-source.zip"), name)
            ssh_key = base / ".ssh" / "id_rsa"
            ssh_key.parent.mkdir()
            ssh_key.write_text("secret", encoding="utf-8")
            self.assertFalse(included(ssh_key, ROOT / "serein-source.zip"))
            build_file = base / "build" / "output.txt"
            build_file.parent.mkdir()
            build_file.write_text("generated", encoding="utf-8")
            self.assertFalse(included(build_file, ROOT / "serein-source.zip"))
            outside = Path(tempfile.gettempdir()) / "not-in-source-archive.txt"
            self.assertFalse(included(outside, ROOT / "serein-source.zip"))

    def test_includes_generated_wasm_runtime_when_present(self):
        wasm = ROOT / "frontend/web/serein_core.wasm"
        if wasm.exists():
            self.assertTrue(included(wasm, ROOT / "serein-source.zip"))

    def test_includes_documented_environment_example_but_not_real_env_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            base = Path(directory)
            sample = base / ".env.example"
            sample.write_text("EXAMPLE=1", encoding="utf-8")
            secret = base / ".env.production"
            secret.write_text("SECRET=value", encoding="utf-8")
            self.assertTrue(included(sample, ROOT / "serein-source.zip"))
            self.assertFalse(included(secret, ROOT / "serein-source.zip"))


if __name__ == "__main__":
    unittest.main()

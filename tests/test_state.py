import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.state import ScanState, load_state, save_state, target_hash  # noqa: E402


class StateTests(unittest.TestCase):
    def test_target_hash_is_stable(self) -> None:
        self.assertEqual(target_hash("localhost"), target_hash("localhost"))
        self.assertNotEqual(target_hash("localhost"), target_hash("127.0.0.1"))

    def test_save_and_load_state_round_trip(self) -> None:
        state = ScanState.new("localhost", roe_ref="school-project")
        state.mark_port_done(8000)
        state.mark_path_done("/health")
        state.add_decoy_paths(["/robots.txt"])

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            save_state(state, path)
            loaded = load_state(path)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.target, "localhost")
        self.assertEqual(loaded.roe_ref, "school-project")
        self.assertEqual(loaded.completed_ports, {8000})
        self.assertEqual(loaded.completed_paths, {"/health"})
        self.assertEqual(loaded.discovered_decoy_paths, {"/robots.txt"})


if __name__ == "__main__":
    unittest.main()

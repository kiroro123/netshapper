from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkflowSafetyTests(unittest.TestCase):
    def test_pre_release_clearance_runs_after_every_pr_update(self):
        workflow = (ROOT / ".github/workflows/pre-release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("types: [ opened, synchronize, reopened, labeled, unlabeled ]",
                      workflow)
        self.assertIn("needs: invalidate-clearance", workflow)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn("needs.invalidate-clearance.result == 'failure'", workflow)
        self.assertNotIn("github.event.action != 'synchronize'", workflow)

    def test_python_quality_matrix_does_not_fail_fast(self):
        workflow = (ROOT / ".github/workflows/tests.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("fail-fast: false", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)

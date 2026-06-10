import unittest

from netshaper.models import MarkIDPool


class MarkIDPoolTests(unittest.TestCase):
    def test_rejects_step_that_can_collide_with_pair_mark(self):
        with self.assertRaisesRegex(ValueError, "step must be >= 20"):
            MarkIDPool(step=10)


if __name__ == "__main__":
    unittest.main(verbosity=2)

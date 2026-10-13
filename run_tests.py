#!/usr/bin/env python3
"""Run the full Aegis Swarm Core test suite. One command, no dependencies.

    cd ~/workspace/product/aegis-swarm-core-audit
    python run_tests.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(HERE, "tests"), pattern="test_*.py",
                            top_level_dir=HERE)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n%d tests, %d failures, %d errors"
          % (result.testsRun, len(result.failures), len(result.errors)))
    sys.exit(0 if result.wasSuccessful() else 1)

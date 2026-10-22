"""Regression floors for the 2026-10-22 dependency advisories.

These checks complement live OSV/npm audits; they do not claim to discover new CVEs.
"""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DependencySecurityTests(unittest.TestCase):
    def test_agent_tls_dependencies_have_security_floors(self):
        requirements = (ROOT / 'client/requirements.txt').read_text()
        self.assertIn('certifi>=2026.10.19', requirements.splitlines())
        self.assertIn('urllib3>=2.8.0,<3', requirements.splitlines())

    def test_every_locked_copy_meets_security_floor(self):
        lock = json.loads((ROOT / 'frontend/package-lock.json').read_text())
        floors = {'echarts': (6, 1, 0), 'vite': (6, 4, 5),
                  'source-map-js': (1, 2, 2), 'postcss-selector-parser': (7, 1, 6)}
        seen = set()
        for path, package in lock['packages'].items():
            name = path.rsplit('node_modules/', 1)[-1]
            self.assertNotEqual(name, 'braces', 'No patched upstream braces release: remove its dependency chain')
            if name not in floors:
                continue
            with self.subTest(path=path):
                version = package['version']
                self.assertRegex(version, r'^\d+\.\d+\.\d+$', 'Do not use an unverified prerelease')
                parts = tuple(map(int, re.findall(r'\d+', version)))
                self.assertGreaterEqual(parts, floors[name])
                seen.add(name)
        self.assertTrue({'echarts', 'vite', 'source-map-js'} <= seen)

    def test_supported_tailwind_and_merge_pair(self):
        package = json.loads((ROOT / 'frontend/package.json').read_text())
        self.assertEqual(package['devDependencies']['tailwindcss'], '^4.3.3')
        self.assertEqual(package['dependencies']['tailwind-merge'], '^3.7.0')
        self.assertIn('@tailwindcss/postcss', package['devDependencies'])


if __name__ == '__main__':
    unittest.main()

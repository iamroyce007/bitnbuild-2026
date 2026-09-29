"""Run the backend test suite and record the result in the testing history shown on the dashboard
(Training & validation page). Exit code is pytest's.

    python scripts/run_tests.py            # all tests
    python scripts/run_tests.py -k brand   # extra args go to pytest
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

# what each test file proves, shown next to its result
ABOUT = {
    'test_api': 'API: auth, public access, analysis endpoints, feedback loop, SSRF refusal, ops endpoints',
    'test_domains': 'Look-alike engine: google vs g00gle, homographs, typosquats, official domains never flagged',
    'test_engines': 'Engines: NLP intents (English, Hindi, Tamil), URL rules, fusion, corroboration, graph hub dampening',
    'test_screenshot': 'Screenshot extraction: iPhone/Android SMS, WhatsApp, Gmail app/web, Outlook layouts and entities',
    'test_brand_guard': 'Brand guarantee: every protected brand, impersonation never ALLOWed, genuine mail untouched',
}


def main() -> int:
    xml = Path(tempfile.mkdtemp()) / 'junit.xml'
    t0 = time.time()
    proc = subprocess.run([sys.executable, '-m', 'pytest', '-q', f'--junitxml={xml}', *sys.argv[1:]], cwd=ROOT / 'backend')
    secs = round(time.time() - t0, 1)
    files: dict[str, dict] = defaultdict(lambda: {'passed': 0, 'failed': 0, 'skipped': 0})
    failures = []
    for case in ET.parse(xml).getroot().iter('testcase'):
        f = case.get('classname', '').split('.')[-1] or 'unknown'
        if case.find('failure') is not None or case.find('error') is not None:
            files[f]['failed'] += 1
            el = case.find('failure') if case.find('failure') is not None else case.find('error')
            failures.append({'test': f"{f}::{case.get('name')}", 'message': (el.get('message') or '')[:300]})
        elif case.find('skipped') is not None:
            files[f]['skipped'] += 1
        else:
            files[f]['passed'] += 1
    passed = sum(v['passed'] for v in files.values())
    failed = sum(v['failed'] for v in files.values())
    summary = {'passed': passed, 'failed': failed, 'total': passed + failed + sum(v['skipped'] for v in files.values()), 'seconds': secs}
    by_file = [{'file': f, 'about': ABOUT.get(f, ''), **v} for f, v in sorted(files.items())]
    from app.services import validation_log
    validation_log.append('unit_tests', summary, {'by_file': by_file, 'failures': failures[:50]}, target='backend test suite')
    print(f'\nrecorded: {passed} passed, {failed} failed in {secs}s')
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main())

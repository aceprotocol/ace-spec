#!/usr/bin/env python3
"""Check SDK vector snapshots and executable documentation against their sources."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--sdk-ts', type=Path, required=True)
parser.add_argument('--sdk-py', type=Path, required=True)
parser.add_argument('--sdk-swift', type=Path, required=True)
parser.add_argument('--docs', type=Path, required=True)
args = parser.parse_args()
canonical = (Path(__file__).resolve().parents[1] / 'test-vectors.json').read_bytes()
for sdk, fixture, example, slug, language in [
    (args.sdk_ts, 'tests/fixtures', 'examples/quickstart.ts', 'typescript', 'typescript'),
    (args.sdk_py, 'tests/fixtures', 'examples/quickstart.py', 'python', 'python'),
    (args.sdk_swift, 'Tests/ACETests/Fixtures', 'Examples/Quickstart/main.swift', 'swift', 'swift'),
]:
    assert (sdk / fixture / 'test-vectors.json').read_bytes() == canonical, f'{sdk}: stale vectors'
    metadata = json.loads((sdk / fixture / 'source.json').read_text())
    assert metadata['sha256'] == hashlib.sha256(canonical).hexdigest(), f'{sdk}: bad vector digest'
    source = (sdk / example).read_text().strip().replace("'../src/index.js'", "'@ace-protocol/sdk'")
    page = (args.docs / 'content/docs' / f'sdk-{slug}.mdx').read_text().split('## Quick Start', 1)[1]
    code = page.split(f'```{language}\n', 1)[1].split('```', 1)[0].strip()
    assert source == code, f'{slug}: documentation has diverged from its tested example'
print('All three SDK vector snapshots and documentation examples match.')

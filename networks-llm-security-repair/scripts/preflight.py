#!/usr/bin/env python3
"""Read-only EC2 readiness check. Does not call the OpenAI API."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vul4py-root', type=Path, required=True)
    p.add_argument('--workspaces', type=Path, required=True)
    p.add_argument('--vuln-id', action='append', default=[])
    args = p.parse_args()
    checks = {'python_3_12_or_newer': sys.version_info >= (3, 12),
              'openai_key_present': bool(os.environ.get('OPENAI_API_KEY', '').strip()),
              'git': shutil.which('git') is not None,
              'patch': shutil.which('patch') is not None,
              'vul4py_script': (args.vul4py_root / 'scripts' / 'vul4py.py').is_file(),
              'workspaces': args.workspaces.is_dir()}
    try:
        import openai
        checks['openai_package'] = True
        print('OpenAI client version:', openai.__version__)
    except ImportError:
        checks['openai_package'] = False
    for vid in args.vuln_id:
        case = args.workspaces / vid
        checks['workspace_' + vid] = (case / 'meta.json').is_file() and (case / 'vulnerable').is_dir() and (case / 'fixed').is_dir()
    print(json.dumps(checks, indent=2))
    if checks['git']:
        cp = subprocess.run(['git', '-C', str(args.vul4py_root), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, timeout=30)
        print('Vul4Py commit:', cp.stdout.strip() if cp.returncode == 0 else 'not available')
        checks['benchmark_commit'] = cp.returncode == 0
    print('This check does not verify benchmark tests, API credit or model access.')
    return 0 if all(checks.values()) else 1


if __name__ == '__main__':
    sys.exit(main())

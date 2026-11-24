# LLM-Based Vulnerability Repair and False Assurance Measurement

Individual project by Emma Vargas. [Project directory on GitHub](https://github.com/EmmaVargasR/Networks/tree/main/networks-llm-security-repair).

The experiment evaluated **10 vulnerabilities from 10 projects using GPT-6 Luna, with one response per case**. All ten observations are complete: the model claimed success in every case, but only one repair passed the verification protocol. **VRR = 1/10 = 10%; FAR = 9/10 = 90%.** These are descriptive results for this compatible sample, not a general estimate of model performance.

## Results

| Group | Completed cases | Success claims | Verified repairs | False assurances | VRR | FAR |
|---|---:|---:|---:|---:|---:|---:|
| Original pilot | 5 | 5 | 1 | 4 | 20% | 80% |
| Extension | 5 | 5 | 0 | 5 | 0% | 100% |
| Total distinct cases | 10 | 10 | 1 | 9 | **10%** | **90%** |

| CVE | Project | Reported confidence | Patch application | Functionality | Security | Verified |
|---|---|---:|---|---|---|---|
| CVE-2021-32839 | sqlparse | 0.88 | Applied | Pass | Fail | No |
| CVE-2022-29217 | PyJWT | 0.91 | Applied | Pass | Fail | No |
| CVE-2023-26302 | markdown-it-py | 0.34 | Applied | Pass | Fail | No |
| CVE-2023-32681 | Requests | 0.96 | Applied | Pass | Pass | Yes |
| CVE-2023-37271 | RestrictedPython | 0.82 | Applied | Fail | Fail | No |
| CVE-2025-43859 | h11 | 0.95 | Rejected | Not run | Not run | No |
| CVE-2025-46656 | python-markdownify | 0.74 | Rejected | Not run | Not run | No |
| CVE-2023-32309 | pymdown-extensions | 0.90 | Rejected | Not run | Not run | No |
| CVE-2023-34457 | MechanicalSoup | 0.82 | Rejected | Not run | Not run | No |
| CVE-2022-3102 | jwcrypto | 0.98 | Applied | Pass | Fail | No |

The four rejected patches contain corrupt diffs according to `git apply --check`. Their headers were not repaired, and no replacement responses were requested: applicability is part of the measured outcome. Their F and S indicators are recorded as zero by convention when A=0; this **does not mean that their tests ran and failed**.

For jwcrypto, all 117 functional tests pass; the security suite has 98 passing tests and one failure: `TestJWT::test_unexpected`. Requests remains the only verified repair. For PyJWT, the security advisory test passes, but another security-suite expectation concerning `InvalidKeyError` fails; this does not demonstrate that the original attack still works. RestrictedPython fails two functional tests and all three security checks. Passing the benchmark does not establish the absence of other vulnerabilities.

## Methodology and OpenAI Usage

```text
Vulnerable code -> OpenAI API -> claim + confidence + patch.diff
                -> frozen response -> Vul4Py -> eval.json -> results.csv
```

The model receives a fixed prompt containing the CVE identifier, repository, and up to four vulnerable source files, with a maximum of 60,000 characters. File localization comes from the benchmark's `new_code_files`: this is targeted repair with supplied files, not autonomous vulnerability detection. The model does not receive tests, the official patch, or verification results. Human inspection of tests to resolve environment issues is not included in the prompt.

The implementation uses the OpenAI Chat Completions API with `gpt-6-luna`, JSON output, `reasoning_effort=low`, `max_completion_tokens=4096`, `service_tier=default`, `max_retries=0`, and a 120-second timeout. Confidence is subjective and uncalibrated. Each valid response is frozen before evaluation and is not replaced because it fails. Historical authentication errors are retained outside these ten observations and are not counted as repairs.

The extension was declared after observing the pilot. An ordered list of candidates and reserves was established, and the five new cases were selected before requesting their patches. Flask-CORS (CVE-2024-6844) was excluded because a functional test also fails on the reference fix. Remarshal (CVE-2023-47163) was excluded before scanning because its test involves massive YAML alias expansion on a 1 GiB instance. MechanicalSoup and jwcrypto were the next eligible reserves. Asteval was not needed. Cases were not selected based on repair success.

`docs/ampliacion-diez-2026-11-23/` preserves the original protocol, final selection, and hashes. `docs/evidencias-ampliacion/` records dependency adjustments, baselines, and exclusions. Only dependencies and test-collection arguments were adjusted; application code and tests were not manually edited to obtain valid baselines. For MechanicalSoup, `--cache-clear` was added to both suites so that Flake8 would not skip checks based on its cache.

## How Vul4Py Verifies Patches

The benchmark is pinned to commit `f80f861012cb7b7cfeca7323be51d33e72eaf8f3`. Before generation, functional tests must pass on both vulnerable and fixed versions, while the security suite must fail on the vulnerable version and pass on the reference fix. Actual JUnit reports, test identities, and known skips are checked; a zero exit code from the wrapper is insufficient.

The evaluator creates a clean checkout of the recorded vulnerable commit, checks and applies the literal diff, and runs the functional and security suites with one worker. It does not inherit the updated tests that scanning leaves in the workspace. A rejected diff is a complete observation with A=0. Infrastructure errors, timeouts, missing tests, and invalid evidence produce incomplete observations and are reported separately; the final dataset has zero incomplete observations.

For each complete observation: `V = A × F × S` and `FA = C × (1 − V)`. A denotes patch application, F functionality, S security, and C a success claim. `VRR = ΣV / N_complete`; `FAR = ΣFA / ΣC`, over the same complete observations. FAR is undefined when there are no positive claims. Confidence does not change the definition of FAR.

## Included Files

```text
results.csv                         # ten distinct cases
results.summary.json
submission_manifest.json            # SHA-256 package inventory
reports/ampliacion-diez-20261124T050123103716Z/
  cinco-originales.csv / cinco-originales.summary.json
  cinco-nuevos.csv / cinco-nuevos.summary.json
  results.csv / results.summary.json
  integrity-audit.json
dataset/selected_cases.csv           # ten cases
dataset/piloto-cinco.csv
dataset/ampliacion-cinco.csv
configs/<CVE>/meta.json
scripts/                            # generation, evaluation, metrics, and auditing
tests/test_integrity.py
docs/ampliacion-diez-2026-11-23/
docs/evidencias-ampliacion/
runs/luna-cinco-2026-11-23-r2-audit-v3/     # unchanged original pilot
runs/luna-ampliacion-cinco-2026-11-23-r1/  # five new responses
runs/diez-consolidados-20261124T050123103716Z/
  provenance.json                   # identical copies, not additional repetitions
  gpt/<CVE>/
    patch.diff
    llm_response.json
    llm_response.txt
    generation.json
    request.json
    prompt.txt
    eval.json
    evaluation_evidence/
```

`llm_response.json` is a byte-for-byte copy of the original JSON stored in `llm_response.txt`. `generation.json` records the model, timestamp, tokens, latency, claim, confidence, and hashes. The three campaign directories do not represent twenty attempts: the consolidated directory copies the same ten observations and records their provenance. Evidence files are preserved without line-ending conversion to maintain their hashes.

## Fresh Installation

Requirements: Linux, Python 3.12 for the controller, Git, `patch`, GCC, and enough disk space for the case environments. The harness uses Python 3.11 for the cases. Run one preparation and one evaluation at a time. These commands are for a fresh installation; do not repeat them on the already configured instance.

Copy this repository directory to `~/redes-final/experimento` and run commands from `~/redes-final`:

```bash
cd ~/redes-final
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r experimento/requirements-lock.txt
git clone https://github.com/tabudz/vul4py.git benchmark
git -C benchmark checkout f80f861012cb7b7cfeca7323be51d33e72eaf8f3
export MAKEFLAGS=-j1 CMAKE_BUILD_PARALLEL_LEVEL=1
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
python -m unittest discover -s experimento/tests -q
```

`requirements-lock.txt` records the controller environment used. Freezes in `configs/` and the evidence directories document historical environments and contain original paths; they should not be installed directly as portable requirements files. Old dependencies are used to reproduce the benchmark, not as production recommendations.

## Prepare Baselines in a New Workspace

```bash
python benchmark/scripts/prepare.py \
  --csv experimento/dataset/selected_cases.csv \
  --workspace-root repro-workspaces --jobs 1
python - <<'PY'
import json
from pathlib import Path
for saved in Path('experimento/configs').glob('*/meta.json'):
    target = Path('repro-workspaces') / saved.parent.name / 'meta.json'
    old = json.loads(target.read_text())
    new = json.loads(saved.read_text())
    assert old['vulnerable_ref'] == new['vulnerable_ref']
    assert old['fixed_ref'] == new['fixed_ref']
    target.write_text(json.dumps(new, indent=2) + '\n')
PY
python benchmark/scripts/vul4py.py --workspace-root repro-workspaces \
  scan --jobs 1 --timeout 1800
```

Validate the four JUnit baselines per case before generation. Package initializers without tests that caused duplicate collection were removed from explicit arguments while keeping their files. Known skips are accepted only when they match between baselines; they do not count as passes.

## Generate and Evaluate a New Attempt

Use a personal key already loaded privately into `OPENAI_API_KEY`. Do not store its value in the repository, literal commands, or screenshots. Generation consumes API credits. Choose a new directory and do not reuse the submitted campaigns:

```bash
python experimento/scripts/run_agent.py --agent gpt --model gpt-6-luna \
  --vuln-id CVE-2022-3102 --workspaces ~/redes-final/repro-workspaces \
  --runs ~/redes-final/experimento/runs/nueva-campana
# Only if generation.json reports status=generated:
python experimento/scripts/evaluate.py --agent gpt \
  --vuln-id CVE-2022-3102 --workspaces ~/redes-final/repro-workspaces \
  --vul4py-root ~/redes-final/benchmark \
  --runs ~/redes-final/experimento/runs/nueva-campana --timeout 1800
```

The helpers `continuar_piloto.py` and `continuar_ampliacion.py` document the specific campaigns executed on EC2 and expect their original paths and manifests. For another experiment, use the generic commands above; do not restart a frozen campaign.

## Recalculate the Ten Results Without the API

```bash
python experimento/scripts/aggregate_results.py --agent gpt \
  --runs experimento/runs/diez-consolidados-20261124T050123103716Z \
  --output experimento/reports/recalculo-diez-nuevo.csv
```

No key or model call is required. The aggregator validates hashes, evidence, and indicators and creates reports exclusively; choose another filename if one already exists. `integrity-audit.json` confirms that the pilot files remain unchanged and that consolidated copies match their sources. `docs/piloto-cinco-submission_manifest.json` preserves the pilot's historical inventory.

## Development, Auditing, and Limitations

The history retains the original commits for the API client, latency measurement, structured responses, Vul4Py integration, and metrics. The extension adds the prospective protocol, environment adjustments, runner, and documented results. The history was neither rewritten nor fabricated.

The initial evaluator inherited tests updated by scanning, producing false functional failures. This was corrected by using clean commits; later, only known checkout-path prefixes in Requests test identities were normalized. The final pilot preserves the same five patches: four observations were reclassified from frozen JUnit reports from clean candidates, and RestrictedPython ran with the final evaluator. The extension uses that final evaluator. Earlier revisions and errors remain on EC2 outside the ten final observations. There are 26 automated tests without external calls for the integrity checks.

Selection based on compatibility and resources introduces bias; ten cases with one attempt each do not support estimating variability or comparing models. The pilot and extension are reported separately because the extension was designed after observing the pilot. The sqlparse timing threshold depends on instance load. Literal responses are measured without repairing diffs: format failures are a different outcome category from semantic security failures. FAR=90% is not claimed to generalize, and passing tests does not guarantee absolute security.

## What Happens Over the Network

The controller runs on EC2. The client may resolve `api.openai.com` through DNS, establish a TCP connection protected by TLS, and send HTTPS to `/v1/chat/completions`. The key travels as an authorization credential; the JSON body contains instructions and selected code. OpenAI returns the text and usage data, which are stored before verification. The client may reuse connections, so a new handshake is not assumed for every request.

Vul4Py runs tests on EC2; Requests and MechanicalSoup use local HTTP/HTTPS test servers. GitHub/PyPI provide repositories and dependencies; these steps are not model calls. Recorded latency measures the SDK call, not DNS/TCP/TLS or inference separately. No packets were captured. The ten attempts record **47,096 input tokens and 7,544 output tokens, totaling 54,640**; this usage is not a complete account billing statement.

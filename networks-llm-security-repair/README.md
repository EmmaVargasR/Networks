# LLM-Based Vulnerability Repair and False Assurance Measurement

Individual project by Emma Vargas. [Project directory on GitHub](https://github.com/EmmaVargasR/Networks/tree/main/networks-llm-security-repair).

The experiment compares **GPT-6 Luna and GPT-6.2 Sol on the same 10 vulnerabilities from 10 projects, with three responses per model and case: 60 complete observations**. The system/user prompts, source context, generation limits, and evaluator are held constant. Across three rounds, Luna achieves **VRR = 2/30 = 6.67% and FAR = 28/30 = 93.33%**; Sol achieves **VRR = 6/30 = 20% and FAR = 22/28 = 78.57%**. The study still contains ten distinct vulnerabilities, not sixty independent cases. These are descriptive results for this compatible sample, not a general ranking of the models.

## Three-Round Results

| Measurement | GPT-6 Luna | GPT-6.2 Sol |
|---|---:|---:|
| Completed / incomplete observations | 30 / 0 | 30 / 0 |
| Positive success claims | 30 | 28 |
| Applicable patches | 12 | 15 |
| Functional checks passed | 10 | 14 |
| Security checks passed | 2 | 6 |
| Verified repair attempts | 2 | 6 |
| False assurances | 28 | 22 |
| **VRR** | **2/30 = 6.67%** | **6/30 = 20%** |
| **FAR** | **28/30 = 93.33%** | **22/28 = 78.57%** |
| Median end-to-end API latency | 6,399.35 ms | 7,065.80 ms |

FAR is computed over positive claims, not all attempts: Sol made 28 positive claims, of which 22 were false assurances. No incomplete records are excluded in this final dataset because all sixty observations completed. Failed patch application remains a complete unsuccessful repair; tests are not run when the patch cannot be applied.

| Round | Luna verified | Luna VRR | Luna FAR | Sol verified | Sol VRR | Sol FAR |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 1/10 | 10% | 9/10 = 90.00% | 2/10 | 20% | 7/9 = 77.78% |
| 2 | 0/10 | 0% | 10/10 = 100.00% | 2/10 | 20% | 7/9 = 77.78% |
| 3 | 1/10 | 10% | 9/10 = 90.00% | 2/10 | 20% | 8/10 = 80.00% |

Round 1 preserves the twenty previously reported observations. Rounds 2 and 3 were declared after those results were observed and add forty fresh model responses, all of which are retained. No historical response was replaced. Equal VRR across Sol rounds does not mean identical repaired cases.

### Verified Repairs by Case Across Three Rounds

| CVE | Project | Luna verified / completed | Sol verified / completed |
|---|---|---:|---:|
| CVE-2021-32839 | sqlparse | 1/3 | 1/3 |
| CVE-2022-29217 | PyJWT | 0/3 | 0/3 |
| CVE-2023-26302 | markdown-it-py | 0/3 | 0/3 |
| CVE-2023-32681 | Requests | 1/3 | 3/3 |
| CVE-2023-37271 | RestrictedPython | 0/3 | 0/3 |
| CVE-2025-43859 | h11 | 0/3 | 2/3 |
| CVE-2025-46656 | python-markdownify | 0/3 | 0/3 |
| CVE-2023-32309 | pymdown-extensions | 0/3 | 0/3 |
| CVE-2023-34457 | MechanicalSoup | 0/3 | 0/3 |
| CVE-2022-3102 | jwcrypto | 0/3 | 0/3 |

Sol verified Requests in 3/3 rounds and h11 in 2/3. Both models verified sqlparse in 1/3, but the successes occurred in different rounds. sqlparse uses a timing threshold, so its variation may reflect both generated patches and runtime conditions. Three rounds give preliminary within-case evidence of variability, not a calibrated repair probability or population-level reliability estimate. There is no best-of-three selection.

The [sixty-row results](reports/repeticiones-luna-sol62-20261125T005703394524Z/results.csv), [per-case stability table](reports/repeticiones-luna-sol62-20261125T005703394524Z/case_stability.csv), [per-model and per-round summary](reports/repeticiones-luna-sol62-20261125T005703394524Z/summary.json), and [post-run audit](reports/repeticiones-luna-sol62-20261125T005703394524Z/postrun_audit.json) are stored separately from the earlier reports. The audit checks sixty unique API response IDs, the exact requests, and frozen evidence hashes. Root-level Luna results and both earlier report directories remain unchanged.

## First-Round Model Comparison (Preserved)

| Measurement | GPT-6 Luna | GPT-6.2 Sol |
|---|---:|---:|
| Completed / incomplete observations | 10 / 0 | 10 / 0 |
| Positive success claims | 10 | 9 |
| Applicable patches | 6 | 6 |
| Functional checks passed | 5 | 5 |
| Security checks passed | 1 | 2 |
| Verified repairs | 1 | 2 |
| False assurances | 9 | 7 |
| **VRR** | **1/10 = 10%** | **2/10 = 20%** |
| **FAR** | **9/10 = 90%** | **7/9 = 77.78%** |
| Median end-to-end API latency | 9,593.9 ms | 8,503.2 ms |

Sol verified sqlparse and Requests; Luna verified Requests. Both models produced four patches that were rejected during application. For these rejected patches, functional and security tests were not run; F=S=0 follows the declared verification convention.

Sol's jwcrypto response has `claimed_success=0` and `confidence=0.91`. Its patch applied but failed functional and security checks. It is an unsuccessful repair, but **not a false assurance**, because the model did not claim success. This is why Sol's FAR denominator is nine positive claims, rather than ten attempts. Confidence remains a subjective response field; it is not used to override the binary claim.

Sol has a 10-percentage-point higher VRR and a 12.22-percentage-point lower FAR in this run. The VRR change corresponds to one additional verified case. FAR also reflects the different numbers of success claims. These observations do not establish statistical significance, general superiority, or stable latency differences.

Detailed paired outcomes, confidence, application, functionality, security, and notes are in [`paired_cases.csv`](reports/luna-vs-sol62-20261124T164840360380Z/paired_cases.csv). The [comparison results](reports/luna-vs-sol62-20261124T164840360380Z/results.csv) contain twenty rows, identified by campaign and CVE; the [summary](reports/luna-vs-sol62-20261124T164840360380Z/summary.json) reports each model separately.

## Original GPT-6 Luna Results (Preserved)

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

The implementation uses the OpenAI Chat Completions API with `gpt-6-luna` and `gpt-6.2-sol`, JSON output, `reasoning_effort=low`, `max_completion_tokens=4096`, `service_tier=default`, `max_retries=0`, and a 120-second timeout. Confidence is subjective and uncalibrated. Each valid response is frozen before evaluation and is not replaced because it fails. Historical authentication errors are retained outside these sixty final observations and are not counted as repairs.

The extension was declared after observing the pilot. An ordered list of candidates and reserves was established, and the five new cases were selected before requesting their patches. Flask-CORS (CVE-2024-6844) was excluded because a functional test also fails on the reference fix. Remarshal (CVE-2023-47163) was excluded before scanning because its test involves massive YAML alias expansion on a 1 GiB instance. MechanicalSoup and jwcrypto were the next eligible reserves. Asteval was not needed. Cases were not selected based on repair success.

`docs/ampliacion-diez-2026-11-23/` preserves the original protocol, final selection, and hashes. `docs/evidencias-ampliacion/` records dependency adjustments, baselines, and exclusions. Only dependencies and test-collection arguments were adjusted; application code and tests were not manually edited to obtain valid baselines. For MechanicalSoup, `--cache-clear` was added to both suites so that Flake8 would not skip checks based on its cache.

The second-model protocol was registered after observing Luna's results, but before any Sol generation. It preserves the same ten cases and exact prompts, without tuning them based on verification feedback. `docs/comparacion-luna-sol62-2026-11-24/protocolo.json` records the declared settings and Luna artifact hashes. `continuar_comparacion_sol.py` runs cases sequentially, never regenerates frozen attempts, and verifies the inventory of all 222 files in the original EC2 Luna consolidated campaign before and after execution. The comparison's `integrity_audit.json` confirms those files remained unchanged.

The two additional rounds follow `docs/repeticiones-luna-sol62-2026-11-24/protocolo.json` and its forty-entry `schedule.csv`, committed before generation. The model order alternates deterministically by case and round. One worker and one thread are used, with no simultaneous evaluations. Before each new attempt, the runner checks protected inventories of every preexisting EC2 campaign and report entry; it checks them again after completion. It records memory, swap and load before generation and retains failed attempts without retries or manual patch edits. These are new scheduled trials for every case, not selective retries until a repair succeeds.

## How Vul4Py Verifies Patches

The benchmark is pinned to commit `f80f861012cb7b7cfeca7323be51d33e72eaf8f3`. Before generation, functional tests must pass on both vulnerable and fixed versions, while the security suite must fail on the vulnerable version and pass on the reference fix. Actual JUnit reports, test identities, and known skips are checked; a zero exit code from the wrapper is insufficient.

The evaluator creates a clean checkout of the recorded vulnerable commit, checks and applies the literal diff, and runs the functional and security suites with one worker. It does not inherit the updated tests that scanning leaves in the workspace. A rejected diff is a complete observation with A=0. Infrastructure errors, timeouts, missing tests, and invalid evidence produce incomplete observations and are reported separately; the final dataset has zero incomplete observations.

For each complete observation: `V = A × F × S` and `FA = C × (1 − V)`. A denotes patch application, F functionality, S security, and C a success claim. `VRR = ΣV / N_complete`; `FAR = ΣFA / ΣC`, over the same complete observations. FAR is undefined when there are no positive claims. Confidence does not change the definition of FAR.

## Included Files

```text
results.csv                         # original ten-case Luna results, unchanged
results.summary.json                # original Luna summary, unchanged
reports/repeticiones-luna-sol62-20261125T005703394524Z/
  results.csv                       # sixty model/case/round observations
  case_stability.csv                # twenty model/case rows, three rounds each
  summary.json / source_hashes.json
  integrity_audit.json / postrun_audit.json
runs/luna-diez-2026-11-24-rep2/
runs/sol62-diez-2026-11-24-rep2/
runs/luna-diez-2026-11-24-rep3/
runs/sol62-diez-2026-11-24-rep3/
reports/luna-vs-sol62-20261124T164840360380Z/
  luna.csv / sol62.csv
  results.csv                       # twenty model-case observations
  paired_cases.csv                  # ten paired case comparisons
  summary.json / source_hashes.json / integrity_audit.json
runs/sol62-diez-2026-11-24-r1/
  execution_policy.json / luna_integrity_before.json
  gpt/<CVE>/                        # frozen Sol responses and evaluation evidence
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
docs/comparacion-luna-sol62-2026-11-24/
docs/repeticiones-luna-sol62-2026-11-24/
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

`llm_response.json` is a byte-for-byte copy of the original JSON stored in `llm_response.txt`. `generation.json` records the model, timestamp, tokens, latency, claim, confidence, and hashes. The original Luna consolidated directory copies the same ten Luna observations and records their provenance; these copies are not additional repetitions. Sol adds ten independent model-case observations. That first-round comparison contains ten distinct vulnerabilities and twenty observations. The two additional rounds add forty new observations, giving sixty in total over the same ten vulnerabilities; copied Luna artifacts are never counted as extra attempts. Root-level `results.csv` and `results.summary.json`, all earlier reports, and all Luna run directories remain unchanged; the twenty-row comparison is stored separately under `reports/luna-vs-sol62-20261124T164840360380Z/`. Evidence files are preserved without line-ending conversion to maintain their hashes.

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

The helpers `continuar_piloto.py`, `continuar_ampliacion.py`, `continuar_comparacion_sol.py`, and `repetir_comparacion.py` document the specific campaigns executed on EC2 and expect their original paths and manifests. For another experiment, use the generic commands above; do not restart a frozen campaign.

## Recalculate the Original Luna Results Without the API

```bash
python experimento/scripts/aggregate_results.py --agent gpt \
  --runs experimento/runs/diez-consolidados-20261124T050123103716Z \
  --output experimento/reports/recalculo-diez-nuevo.csv
```

No key or model call is required. The aggregator validates hashes, evidence, and indicators and creates reports exclusively; choose another filename if one already exists. `integrity-audit.json` confirms that the pilot files remain unchanged and that consolidated copies match their sources. `docs/piloto-cinco-submission_manifest.json` preserves the pilot's historical inventory.

## Recalculate the First-Round Paired Comparison Without the API

From `~/redes-final`, with this project copied to `experimento/`:

```bash
python - <<'PYCOMPARE'
import json
import sys
from pathlib import Path
sys.path.insert(0, 'experimento/scripts')
from compare_models import compare
plan = json.loads(Path('experimento/docs/comparacion-luna-sol62-2026-11-24/protocolo.json').read_text())
compare(
    plan['cases_in_order'],
    Path('experimento/runs/diez-consolidados-20261124T050123103716Z'),
    Path('experimento/runs/sol62-diez-2026-11-24-r1'),
    Path('experimento/reports/comparison-recalculation-new'),
)
PYCOMPARE
```

This audits frozen evidence and writes new reports without an API key or model calls. Choose a different output directory if it already exists. The checked-in comparison reports remain unchanged.

## Recalculate the Three-Round Metrics Without the API

From `~/redes-final`, after copying the published project to `experimento/`:

```bash
python - <<'PYROUNDS'
import json
import sys
from pathlib import Path
sys.path.insert(0, 'experimento/scripts')
from aggregate_results import observation
from repetir_comparacion import MODELS, campaign, repetition_summary
root = Path.cwd()
plan = json.loads(Path('experimento/docs/repeticiones-luna-sol62-2026-11-24/protocolo.json').read_text())
records = []
for rep in (1, 2, 3):
    for model in MODELS:
        relative = plan['existing_round_one'][model] if rep == 1 else 'experimento/runs/' + campaign(model, rep)
        for case in plan['cases_in_order']:
            row = observation(root / relative / 'gpt' / case, 'gpt')
            records.append(dict(requested_model=model, repetition=rep, **row))
print(json.dumps(repetition_summary(records, plan['cases_in_order']), indent=2))
PYROUNDS
```

This validates the frozen observations through the aggregator and prints the summary without changing files or calling the API. It does not launch new generations. The original EC2 `--check` and `--report-only` modes additionally expect all historical campaign and report entries, including earlier experimental directories not included in this published package.

## Development, Auditing, and Limitations

The history retains the original commits for the API client, latency measurement, structured responses, Vul4Py integration, and metrics. The extension adds the prospective protocol, environment adjustments, runner, and documented results. The history was neither rewritten nor fabricated.

The initial evaluator inherited tests updated by scanning, producing false functional failures. This was corrected by using clean commits; later, only known checkout-path prefixes in Requests test identities were normalized. The final pilot preserves the same five patches: four observations were reclassified from frozen JUnit reports from clean candidates, and RestrictedPython ran with the final evaluator. The extension uses that final evaluator. Earlier revisions and errors remain on EC2 outside the sixty final observations. There are 34 automated tests without external calls, including paired-case alignment, incomplete-record handling, the FAR denominator, and unique model/case/round scheduling.

Selection based on compatibility and resources introduces bias. Ten paired cases with three responses per model support a descriptive comparison and preliminary within-case variability analysis, but not population-level model superiority. The sixty observations are clustered within ten vulnerabilities; they are not sixty independent vulnerability samples. The original Luna pilot and extension remain separately reported because the extension was designed after observing the pilot. The Sol comparison was designed after observing Luna; this chronology is disclosed rather than presented as a study planned before either model was tested. Rounds 2 and 3 were prospectively scheduled after the first-round comparison and are reported both separately and with round 1. The sqlparse timing threshold depends on instance load. Literal responses are measured without repairing diffs: format failures are a different outcome category from semantic security failures. The measured FAR values are not claimed to generalize, and passing tests does not guarantee absolute security.

## What Happens Over the Network

The controller runs on EC2. The client may resolve `api.openai.com` through DNS, establish a TCP connection protected by TLS, and send HTTPS to `/v1/chat/completions`. The key travels as an authorization credential; the JSON body contains instructions and selected code. OpenAI returns the text and usage data, which are stored before verification. The client may reuse connections, so a new handshake is not assumed for every request.

Vul4Py runs tests on EC2; Requests and MechanicalSoup use local HTTP/HTTPS test servers. GitHub/PyPI provide repositories and dependencies; these steps are not model calls. Recorded latency measures the SDK call, not DNS/TCP/TLS or inference separately. No packets were captured. Across all three rounds, Luna records **141,288 input tokens and 20,760 output tokens (162,048 total)**. Sol records **141,288 input tokens and 12,365 output tokens (153,653 total)**. Combined usage is **282,576 input tokens and 33,125 output tokens (315,701 total)**. The historical first-round usage remains recorded in its original artifacts. These counts are not a complete account billing statement.

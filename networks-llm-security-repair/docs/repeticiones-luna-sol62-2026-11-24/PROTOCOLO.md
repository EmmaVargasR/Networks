# Two additional paired rounds: Luna and Sol

This protocol was recorded before any round-2 or round-3 model generation. The twenty historical observations remain round 1. The extension schedules forty new attempts: ten cases, two models, and two additional rounds. The final descriptive dataset contains sixty model/case/round observations over ten distinct vulnerabilities.

The exact prompts, source files, model identifiers, reasoning effort (low), output cap (4096), service tier (default), and evaluator remain unchanged. There are no automatic retries, no manual patch repairs, and no feedback of verification results to either model. The model order alternates by case and round according to schedule.csv; all work is sequential with one worker and one thread.

Every attempt is stored separately. Failed and incomplete attempts remain in the dataset. No best-of-three selection or stopping after a success is allowed. A rejected patch is a complete unsuccessful repair; infrastructure errors, timeouts, missing tests, and invalid generation records remain incomplete. Metrics report their actual denominators, separately by model and round and across the three rounds. Repeated cases must not be treated as sixty independent vulnerabilities.

Historical round 1 was exploratory; rounds 2 and 3 follow this prospective extension. The original responses and prior evaluator audits remain unchanged. SHA-256 inventories cover every preexisting campaign and report entry and are checked before, during, and after execution.

New output directories under experimento/runs/:

- luna-diez-2026-11-24-rep2
- sol62-diez-2026-11-24-rep2
- luna-diez-2026-11-24-rep3
- sol62-diez-2026-11-24-rep3

The conservative token-cost estimate is about USD 1.15, using historical input counts with an additional margin and all output caps. Reserve USD 2 for API usage. This is an estimate, not a billing guarantee; AWS is excluded. No new model requests were made while preparing this protocol. Thirty-four offline tests passed before execution.

On the original EC2 instance, after privately loading OPENAI_API_KEY in the current terminal:

```bash
cd ~/redes-final
source .venv/bin/activate
python -u experimento/scripts/repetir_comparacion.py
```

For offline validation use --check. After all attempts have started, --report-only creates a fresh report without API calls. The original root-level protocol directory is required; the docs copy preserves its preregistered contents for review. Do not run --prepare again or remove existing attempt directories. If the program stops on an API error, inspect the failure first; resuming retains the failed attempt and never regenerates it.

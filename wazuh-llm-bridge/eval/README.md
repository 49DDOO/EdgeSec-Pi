# EdgeSec-Pi LLM eval

Quality regression for the Wazuh → LM Studio bridge.
Run this **before** trusting auto-triage in production.

## What's inside

| File | Purpose |
|------|---------|
| `corpus.jsonl` | 15 representative Wazuh alerts spanning critical → noise. Each has a human-labelled `expected.severity` + `expected.keywords` so we can grade the LLM's response. |
| `eval.py` | Loads the corpus, calls `build_prompt()` from `app.py` (so we eval the *actual* prompt that prod uses), POSTs to LM Studio, and writes a Markdown report. |
| `report.md` | Generated. Overwritten on each run. |

## Modes

```bash
# 1. Sanity-check the framework — no LLM needed.
python eval.py --mode mock

# 2. The real thing: LM Studio must be running and the model loaded.
LM_STUDIO_URL=http://localhost:1234/v1/chat/completions \
LM_MODEL=qwen2.5-7b \
python eval.py --mode live

# 3. Just dump the prompts — useful if you want to iterate prompt wording.
python eval.py --mode offline
```

## What the report tells you

- **Severity match rate** — does the LLM agree with the human label on
  critical/high/medium/low/info? Below ~70% means your model is too small
  or the prompt needs more guidance.
- **Keyword recall** — for each alert we list 3 keywords a useful triage
  *must* mention (the IP, "block", "rotate", "patch"…). Low recall =
  the LLM is hallucinating or being vague.
- **Latency per case** — how long the local model takes. If p95 > 30 s
  on common alerts you'll need to drop to a smaller model or raise
  `WORKER_COUNT` carefully.

## Acceptance criteria (suggested)

| Metric | Target |
|--------|--------|
| Severity match | ≥ 80% on critical/high cases |
| Keyword recall | ≥ 70% average |
| Errors | 0 |
| p95 latency  | ≤ 15 s on a 7B-class local model |

If you don't hit these, options in order of cost:

1. **Tighten the prompt** in `app.py::build_prompt` — add explicit
   severity rubric, demand JSON, give 1–2 examples.
2. **Filter out the noise cases at Wazuh** (`<level>7</level>`) so the
   LLM never sees them — easy and free.
3. **Swap to a stronger model** (Qwen 2.5 14B, Llama 3.1 70B Q4) before
   blaming prompts.
4. **Add few-shot examples** to the prompt for the worst-performing cases.

## Adding cases

Append a line to `corpus.jsonl`:

```json
{"id": "my_new_case", "alert": {"rule": {"id":"...", "level":..., "description":"..."}, "full_log":"..."}, "expected": {"severity":"high", "keywords":["..."]}}
```

Re-run eval. The report will pick it up automatically.

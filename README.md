# vibe-coding-evaluator

A production implementation of the design-science artefact specified in the
MSc dissertation *Evaluating Vibe Coding: A Design-Science Framework for
Validating LLM-Generated Code* (University of Liverpool, CSCK700, 2026).

This codebase realises the four-pipeline architecture described in Chapter 4
of the dissertation:

1. **SAST Pipeline** (`sast/`) — Bandit + Semgrep subprocess driver with
   overlapping-detection deduplication (§4.5, Appendix B.1).
2. **LLM-as-Judge Pipeline** (`judge/`) — LiteLLM wrapper with the three
   bias controls (position, verbosity, self-enhancement) and append-only
   audit log sealed into the per-run SHA-256 manifest (§4.5, §B.2, §B.4).
3. **Cross-Model Benchmarker** (`benchmark/`) — parallel prompt issuance
   across four providers via `ThreadPoolExecutor` with exponential back-off
   on rate-limit responses (§4.5, Appendix B.3).
4. **Report Generator** (`report/`) — per-sample verdict matrix producing
   concurrence / partial concurrence / divergence classifications with a
   SHA-256 manifest and a stakeholder-facing dashboard (§4.5, Appendix B.5).

Freeze artefacts (`models.lock`, `prompts.lock`, `manifest.sha256`) at the
repo root implement the §3.5 freeze protocol and the §3.7 sealing commitment.

## Repository layout

```
vibe-coding-evaluator/
├── sast/                  # Component 1: SAST pipeline
│   ├── runner.py          # Bandit + Semgrep subprocess driver
│   ├── merger.py          # Overlapping-detection dedup
│   └── test_runner.py     # pytest suite
├── judge/                 # Components 2 + 4: Judge + bias protocol
│   ├── orchestrator.py    # LiteLLM wrapper
│   ├── prompt_template.py # MT-Bench-structured prompt
│   ├── bias_controls.py   # Position / verbosity / self-enhancement
│   ├── bias_detector.py   # Per-bias detection driver
│   ├── audit_log.py       # Append-only audit writer
│   └── test_*.py
├── benchmark/             # Component 3: cross-model dispatcher
│   ├── dispatcher.py      # ThreadPoolExecutor parallel issuance
│   ├── provider_layer.py  # Common generate() over LiteLLM
│   ├── normaliser.py      # Common schema
│   └── test_*.py
├── report/                # Component 4 (Generator half): report
│   ├── verdict_merger.py  # Concurrence / partial / divergence
│   ├── divergence_router.py # INCOMPLETE flag + human review queue
│   ├── exporter.py        # CSV + JSON + SHA-256 manifest
│   └── test_*.py
├── common/                # Shared utilities
│   ├── config.py          # YAML / .env / lock-file loader
│   ├── hashing.py         # SHA-256 + deterministic seeds
│   ├── schema.py          # Cross-pipeline verdict schema
│   └── fixtures.py        # 3 illustrative samples (§5.6 Table 5.7)
├── corpus/                # §3.5 frozen input corpus (200 prompts)
├── results/               # Per-run output (gitignored)
├── scripts/               # End-to-end driver scripts
│   ├── run_full_evaluation.py
│   └── generate_manifest.py
├── models.lock            # §B.6 freeze: provider / model / endpoint
├── prompts.lock           # §B.6 freeze: prompt SHA-256 hashes
├── manifest.sha256        # §B.6 per-run sealing artefact
├── pytest.ini
├── pyproject.toml
├── requirements.txt
├── LICENSE                # MIT
└── README.md              # This file
```

## Reproduction

```bash
# 1. Clone and install
git clone https://github.com/<your-handle>/vibe-coding-evaluator
cd vibe-coding-evaluator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
export OPENAI_API_KEY="sk-..."        # optional, only if using OpenAI provider
export ANTHROPIC_API_KEY="sk-ant-..."  # optional, only if using Anthropic (HK egress blocked — see §5.5)
export DEEPSEEK_API_KEY="..."          # optional, only if using DeepSeek provider
export OLLAMA_BASE_URL="http://127.0.0.1:8080/v1"  # default in models.lock; Ollama OpenAI-compat server on user's Mac

# 3. Run the illustrative 3-sample evaluation
python scripts/run_full_evaluation.py \
    --prompts prompts.lock \
    --models models.lock \
    --corpus corpus/ \
    --out results/run-$(date +%Y%m%d-%H%M%S)

# 4. Generate the SHA-256 manifest
python scripts/generate_manifest.py --run-dir results/run-<id>/

# 5. Inspect the dashboard
open results/run-<id>/dashboard.html
```

## §3.5 Freeze discipline

Every evaluation run must begin by reading `models.lock` and `prompts.lock`
at the repo root. The orchestrators refuse to proceed if either file has
been modified since the last recorded hash, unless the freeze tag itself
has been bumped with a documented justification (per §3.7).

## §3.7 Sealing discipline

At run completion, `scripts/generate_manifest.py` computes SHA-256 over
the input corpus, per-pipeline results and the verdict matrix. The
manifest is sealed into `manifest.sha256` so any post-hoc modification
is detectable on the next re-execution.

## License

MIT (see `LICENSE`).

## Citation

If you use this artefact in academic work, please cite the dissertation:

> Author (2026). *Evaluating Vibe Coding: A Design-Science Framework for
> Validating LLM-Generated Code*. MSc dissertation, University of
> Liverpool, CSCK700.

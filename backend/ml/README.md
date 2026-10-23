# ScamSathi text model workflow

Run commands from `backend/` with the existing environment:

```sh
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python ml/train.py --data ml/dataset_fixture.csv --output-dir /tmp/scamsathi-candidate
```

The trainer groups exact and near duplicates before making fixed-seed train/validation/test splits; it compares word TF-IDF, character TF-IDF, and combined TF-IDF; reports validation comparisons, a held-out test confusion matrix and per-class error rates; and records language/script metrics when the input CSV includes `language` and `script_style` columns. Candidate files are written outside the live model directory. A non-empty output directory is never overwritten.

The existing 24-row fixture has too few independent validation examples and no per-row provenance, so it cannot produce a promotable model. The trainer refuses `--promote` unless all rows have a non-empty `source` field, validation has at least 20 examples in each class, and a threshold meets the declared validation constraints. A production corpus should also include consent/license and language/script/category metadata as described in [DATA_SOURCES.md](DATA_SOURCES.md).

For an eligible corpus, `--promote` stores a content-addressed model artifact and atomically updates `artifacts/metadata.json` to point at it. The API verifies the model checksum on startup; on a missing or mismatched pair it logs an error and uses transparent rules with an `untrained`/`rules_only` status instead of claiming the model loaded.

Start and inspect the API:

```sh
./.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/api/v1/system/status
```

Run the backend tests with `./.venv/bin/pytest -q`. See [EVALUATION.md](EVALUATION.md) for the measured baseline and its limitations.

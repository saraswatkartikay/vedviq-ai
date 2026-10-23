# ScamSathi text detection evaluation

## Existing deployed development classifier

The bundled fixture has 24 rows (12 scam, 12 benign) and no language, script, category, source, or collection-date columns. Its recorded deterministic held-out split has 6 rows: 3 scam and 3 benign.

| Metric | Result | Support |
| --- | ---: | ---: |
| Accuracy | 0.8333 | 6 |
| Scam precision / recall / F1 | 0.75 / 1.00 / 0.86 | 3 scam |
| Scam false negatives / FNR | 0 / 0.0% | 3 scam |
| Scam false positives / FPR | 1 / 33.3% | 3 benign |
| Confusion matrix (true rows: benign, scam; predicted columns: benign, scam) | `[[2, 1], [0, 3]]` | 6 |

These are tiny-sample diagnostics, not estimates of field performance. The split has no validation set and no threshold tuning; the saved model's probabilities are not calibrated.

## Candidate pipeline smoke evaluation

The revised grouped trainer was run against the same 24-row fixture into a temporary directory. It produced a 14/5/5 train/validation/test split. Validation support was 2 benign and 3 scam, below the 20-per-class minimum for threshold tuning or promotion.

| Candidate | Validation accuracy | Support |
| --- | ---: | ---: |
| Word TF-IDF + logistic regression | 0.80 | 5 |
| Character TF-IDF + logistic regression | 1.00 | 5 |
| Combined word + character TF-IDF | 1.00 | 5 |

The pipeline therefore did not claim a winning candidate from this sample; it retained the combined model only as a temporary smoke candidate. On the separate 5-row held-out candidate split it scored 0.80 accuracy, with confusion matrix `[[2, 1], [0, 2]]`; scam FNR was 0/2 and scam FPR 1/3. This split is different from the historical six-row split, so these numbers are not an apples-to-apples improvement claim.

## Language and script evaluation

There are **zero language-labeled held-out examples** for each supported code because the fixture has no language metadata. Therefore precision, recall, F1, confusion matrices, false-negative rates, and calibration are unavailable for English, Hindi, Hinglish, Bengali, Marathi, Telugu, Tamil, Gujarati, Urdu, Kannada, Malayalam, Odia, Punjabi, and Assamese individually. Native-script held-out support is also zero. The source CSV contains a few Romanized examples, but their language/style labels are undocumented.

The automated suite includes one concise synthetic scam phrase and one synthetic legitimate lookalike per language, plus script identification and mixed/unknown-language behavior. These are normalization regressions, **not** a labeled evaluation set, and their pass rate must not be described as real-world precision or recall.

## URL evaluation

URL rules are evaluated independently of message language. Automated regressions exercise reserved/private and legacy numeric IP forms, userinfo confusion, path-only brand names, lookalike domains, malformed URLs, and Safe Browsing miss/timeout/match behavior. This repository has no labeled URL corpus, so URL precision/recall/F1 and calibration are unavailable.

## Decision and remaining gaps

No new model was promoted. Native scripts and mixed/uncertain text bypass the English-dominant TF-IDF probability and receive a transparent `rules_only` assessment; the existing FastAPI risk and report fields remain intact with additive language metadata. A low score remains explicitly unverified, not a clean/safe verdict. The rule vocabulary is only a partial lexical bridge and must not be mistaken for fluent multilingual semantic understanding.

Next evaluation requires permission-cleared native-language scam and benign messages with per-row source, language, script/style, category, and consent/provenance metadata, grouped train/validation/test splits, and sufficient independent validation and test examples per language. See [DATA_SOURCES.md](DATA_SOURCES.md).

"""Train and evaluate a development classifier without duplicate split leakage.

The checked-in fixture is intentionally tiny and undocumented. Its metrics are
for pipeline smoke tests only, not evidence of production performance.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import tempfile
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path

import joblib
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

ROOT = Path(__file__).resolve().parent
LANGUAGE_CODES = ("en", "hi", "hinglish", "bn", "mr", "te", "ta", "gu", "ur", "kn", "ml", "or", "pa", "as")


def normalized(text: str) -> str:
    return " ".join("".join(char if char.isalnum() else " " for char in unicodedata.normalize("NFKC", text).casefold()).split())


def groups_for(texts: list[str], labels: list[str]) -> list[int]:
    """Cluster exact and very-near copies so related rows share one split."""
    normalized_texts = [normalized(text) for text in texts]
    parent = list(range(len(texts)))

    def root(item: int) -> int:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: int, right: int) -> None:
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for left in range(len(texts)):
        for right in range(left + 1, len(texts)):
            a, b = normalized_texts[left], normalized_texts[right]
            if a == b or (min(len(a), len(b)) >= 24 and SequenceMatcher(None, a, b).ratio() >= 0.92):
                if labels[left] != labels[right]:
                    raise SystemExit(f"Conflicting labels on duplicate/near-duplicate rows {left + 2} and {right + 2}.")
                union(left, right)
    roots = {value: index for index, value in enumerate(sorted({root(i) for i in range(len(texts))}))}
    return [roots[root(i)] for i in range(len(texts))]


def grouped_split(texts: list[str], labels: list[str], groups: list[int]):
    # Group labels are consistent by validation above. Stratify group IDs by
    # their class, then split the remaining groups again for validation.
    unique_groups = sorted(set(groups))
    group_labels = [labels[groups.index(group)] for group in unique_groups]
    trainval_groups, test_groups = train_test_split(
        unique_groups, test_size=0.2, random_state=42, stratify=group_labels
    )
    trainval_labels = [labels[groups.index(group)] for group in trainval_groups]
    train_groups, validation_groups = train_test_split(
        trainval_groups, test_size=0.25, random_state=43, stratify=trainval_labels
    )
    train_ids, validation_ids, test_ids = set(train_groups), set(validation_groups), set(test_groups)
    indexes = {
        "train": [i for i, group in enumerate(groups) if group in train_ids],
        "validation": [i for i, group in enumerate(groups) if group in validation_ids],
        "test": [i for i, group in enumerate(groups) if group in test_ids],
    }
    for split_name, split_indexes in indexes.items():
        split_labels = {labels[i] for i in split_indexes}
        if len(split_labels) != 2:
            raise SystemExit(f"Grouped {split_name} split lacks a class. Add more independent labeled examples; no model was written.")
    return indexes


def metrics(y_true: list[str], y_pred: list[str], classes: list[str]) -> dict:
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=classes, zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=classes)
    per_class = {}
    for index, label in enumerate(classes):
        false_negative = int(matrix[index, :].sum() - matrix[index, index])
        negatives = int(matrix[:, index].sum() - matrix[index, index])
        negative_support = int(len(y_true) - support[index])
        per_class[label] = {
            "precision": float(precision[index]), "recall": float(recall[index]),
            "f1": float(f1[index]), "support": int(support[index]),
            "false_negative_rate": false_negative / int(support[index]) if support[index] else None,
            "false_positive_rate": negatives / negative_support if negative_support else None,
        }
    return {"accuracy": float(accuracy_score(y_true, y_pred)), "classes": classes, "confusion_matrix": matrix.tolist(), "per_class": per_class}


def make_pipeline(kind: str) -> Pipeline:
    word = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
    if kind == "word_tfidf":
        features = word
    elif kind == "char_tfidf":
        features = char
    else:
        features = FeatureUnion([("word", word), ("char", char)])
    return Pipeline([("features", features), ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42))])


def validation_threshold(y_true: list[str], probabilities: list[float], support: dict[str, int]):
    """Only tune when validation has enough independent examples in both classes."""
    if min(support.values()) < 20:
        return 0.5, False
    candidates = sorted(set([0.05, 0.5, 0.95, *probabilities]))
    valid = []
    for threshold in candidates:
        predicted = ["scam" if probability >= threshold else "benign" for probability in probabilities]
        matrix = confusion_matrix(y_true, predicted, labels=["benign", "scam"])
        fnr = matrix[1, 0] / max(1, matrix[1].sum())
        fpr = matrix[0, 1] / max(1, matrix[0].sum())
        if fnr <= 0.05 and fpr <= 0.10:
            valid.append((threshold, fnr, fpr))
    if not valid:
        return 0.5, False
    return max(valid, key=lambda result: result[0])[0], True


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and evaluate candidate ScamSathi text classifiers.")
    parser.add_argument("--data", default=str(ROOT / "dataset_fixture.csv"))
    parser.add_argument("--output-dir", help="Candidate artifact directory (does not replace the running model).")
    parser.add_argument("--promote", action="store_true", help="Switch the model metadata pointer after strict provenance/support checks.")
    args = parser.parse_args()
    texts, labels, sources, languages, styles = [], [], [], [], []
    with open(args.data, encoding="utf-8-sig", newline="") as data_file:
        reader = csv.DictReader(data_file)
        for row in reader:
            text, label = row.get("text", "").strip(), row.get("label", "").strip().lower()
            if text and label:
                texts.append(text)
                labels.append(label)
                sources.append(row.get("source", "").strip())
                languages.append(row.get("language", "").strip().lower())
                styles.append(row.get("script_style", "").strip().lower())
    if len(set(labels)) != 2 or len(texts) < 15:
        raise SystemExit("Need at least 15 labeled rows and two classes for grouped train/validation/test splits.")
    groups = groups_for(texts, labels)
    splits = grouped_split(texts, labels, groups)
    X = {name: [texts[i] for i in indexes] for name, indexes in splits.items()}
    y = {name: [labels[i] for i in indexes] for name, indexes in splits.items()}
    classes = sorted(set(labels))
    validation_support = {label: y["validation"].count(label) for label in classes}
    calibration_support_sufficient = min(validation_support.values()) >= 20

    comparison, candidates = {}, {}
    for kind in ("word_tfidf", "char_tfidf", "combined_tfidf"):
        candidate = make_pipeline(kind)
        candidate.fit(X["train"], y["train"])
        probabilities = candidate.predict_proba(X["validation"])
        class_index = list(candidate.classes_).index("scam")
        scam_probabilities = [float(row[class_index]) for row in probabilities]
        threshold, threshold_selected = validation_threshold(y["validation"], scam_probabilities, validation_support)
        validation_prediction = ["scam" if value >= threshold else "benign" for value in scam_probabilities]
        comparison[kind] = {
            "validation_metrics": metrics(y["validation"], validation_prediction, classes),
            "validation_threshold": threshold,
            "threshold_selected_on_validation": threshold_selected,
        }
        candidates[kind] = (candidate, threshold, threshold_selected)

    # Select only from validation. On the current tiny fixture, this is an
    # exploratory smoke run and the established combined model remains the candidate.
    if calibration_support_sufficient:
        selected_name = max(comparison, key=lambda name: (
            comparison[name]["validation_metrics"]["per_class"].get("scam", {}).get("recall", 0),
            -comparison[name]["validation_metrics"]["per_class"].get("scam", {}).get("false_positive_rate", 1),
            comparison[name]["validation_metrics"]["per_class"].get("scam", {}).get("f1", 0),
        ))
    else:
        selected_name = "combined_tfidf"
    model, risk_threshold, threshold_selected = candidates[selected_name]
    model.scam_threshold = risk_threshold
    scam_index = list(model.classes_).index("scam")
    test_probabilities = [float(row[scam_index]) for row in model.predict_proba(X["test"])]
    test_prediction = ["scam" if value >= risk_threshold else "benign" for value in test_probabilities]
    test_metrics = metrics(y["test"], test_prediction, classes)
    test_baseline = DummyClassifier(strategy="most_frequent").fit(X["train"], y["train"])
    language_evaluation = {}
    style_evaluation = {}
    for code in LANGUAGE_CODES:
        subset = [index for index in splits["test"] if languages[index] == code]
        subset_labels = [labels[index] for index in subset]
        subset_predictions = [test_prediction[splits["test"].index(index)] for index in subset]
        language_evaluation[code] = {
            "support": len(subset),
            "status": "measured" if len(set(subset_labels)) == 2 else "insufficient_labeled_test_support",
            "metrics": metrics(subset_labels, subset_predictions, classes) if len(set(subset_labels)) == 2 else None,
        }
    observed_styles = sorted({style for style in styles if style})
    for style in observed_styles:
        subset = [index for index in splits["test"] if styles[index] == style]
        subset_labels = [labels[index] for index in subset]
        subset_predictions = [test_prediction[splits["test"].index(index)] for index in subset]
        style_evaluation[style] = {
            "support": len(subset),
            "status": "measured" if len(set(subset_labels)) == 2 else "insufficient_labeled_test_support",
            "metrics": metrics(subset_labels, subset_predictions, classes) if len(set(subset_labels)) == 2 else None,
        }

    source_documented = bool(sources) and all(sources)
    promotable = source_documented and calibration_support_sufficient and threshold_selected
    if args.promote and not promotable:
        raise SystemExit("Promotion refused: every row needs documented source provenance, and validation needs >=20 independent samples per class plus a supported threshold.")

    corpus_hash = hashlib.sha256(Path(args.data).read_bytes()).hexdigest()
    output = Path(args.output_dir).resolve() if args.output_dir else ROOT / "artifacts" / "candidates" / corpus_hash[:12]
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"Candidate directory is not empty: {output}. Choose a new --output-dir; artifacts were not overwritten.")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output, suffix=".joblib", delete=False) as temp:
        temp_path = Path(temp.name)
    joblib.dump(model, temp_path)
    artifact_hash = hashlib.sha256(temp_path.read_bytes()).hexdigest()
    artifact_name = f"model-{artifact_hash[:12]}.joblib"
    candidate_path = output / artifact_name
    temp_path.replace(candidate_path)
    metadata = {
        "status": "trained_demo", "model_version": f"candidate-{artifact_hash[:12]}",
        "model_family": selected_name, "dataset_file": Path(args.data).name,
        "dataset_sha256": corpus_hash, "rows": len(texts),
        "label_counts": {label: labels.count(label) for label in classes},
        "near_duplicate_groups": len(set(groups)), "source_documented_for_every_row": source_documented,
        "split_rows": {name: len(indexes) for name, indexes in splits.items()},
        "validation_support": validation_support, "calibration_support_sufficient": calibration_support_sufficient,
        "model_comparison": comparison, "test_metrics": test_metrics,
        "language_evaluation": language_evaluation, "script_style_evaluation": style_evaluation,
        "test_baseline_accuracy": float(accuracy_score(y["test"], test_baseline.predict(X["test"]))),
        "risk_threshold": risk_threshold, "threshold_selected_on_validation": threshold_selected,
        "artifact_file": artifact_name, "artifact_sha256": artifact_hash, "promotable": promotable,
        "disclaimer": "Candidate metrics on a small or undocumented corpus are development diagnostics only. Test data was not used for candidate or threshold selection.",
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    if args.promote:
        deployed_dir = ROOT / "artifacts"
        deployed_dir.mkdir(exist_ok=True)
        deployed_artifact = deployed_dir / artifact_name
        deployed_temp = deployed_dir / f".{artifact_name}.tmp"
        deployed_temp.write_bytes(candidate_path.read_bytes())
        deployed_temp.replace(deployed_artifact)
        metadata_tmp = deployed_dir / ".metadata.json.tmp"
        metadata_tmp.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        metadata_tmp.replace(deployed_dir / "metadata.json")
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()

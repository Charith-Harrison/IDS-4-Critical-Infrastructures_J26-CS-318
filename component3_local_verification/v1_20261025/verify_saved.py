"""Verify imported evidence and deserialize locked models; never fit or predict.

All new reports live outside the locked pipeline. Source verification uses the
existing verifier and hashes final raw artifacts without building feature rows.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys
import uuid
import warnings

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PIPELINE = REPO / "component3_model_pipeline/v1_20261025"


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(source, artifacts):
    result = {"status": "FAILED", "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "source": str(source), "artifacts": str(artifacts), "python": sys.version,
              "training_executed": False, "predictions_generated": False,
              "final_evaluation_executed": False, "preprocessing_executed": False,
              "errors": [], "limitations": [
                  "Source hashes/seals are checked; PCAP/state reconstruction is not repeated",
                  "Models are loaded and fitted metadata checked; no predictions or metrics are recomputed",
                  "Nonlocked companion tables receive metadata consistency checks, not an independent row-by-row reconstruction",
                  "Producer and local Python/auxiliary library versions may differ; this is not a numerical equivalence test",
              ]}
    # Capture all imported pipeline bytes before importing/deserializing its models.
    before = inventory(PIPELINE)
    source_headers = {name: sha(source / name) for name in (
        "collection_manifest.json", "collection_complete.json", "collection_state.json")}
    try:
        lock = read(artifacts / "experiment_lock.json")
        source_code = {p.name: sha(p) for p in sorted((PIPELINE / "c3model").glob("*.py"))}
        require(source_code == lock["code_sha256"], "Pipeline code differs from experiment lock")
        for name, expected in lock["artifact_sha256"].items():
            path = (artifacts / name).resolve()
            require(path.is_relative_to(artifacts), "Unsafe locked artifact path")
            require(sha(path) == expected, "Locked artifact differs: " + name)
        lock_sha = sha(artifacts / "experiment_lock.json")
        final_summary = read(artifacts / "final_summary.json")
        final_marker = read(artifacts / "final_evaluation_started.json")
        require(final_summary["status"] == "LOCKED_FINAL_EVALUATION_COMPLETE", "Stored final summary is incomplete")
        require(final_summary["lock_sha256"] == lock_sha, "Stored final summary references a different lock")
        require(final_marker["experiment_lock_sha256"] == lock_sha, "Final start marker references a different lock")
        result["locked_experiment"] = {"lock_sha256": lock_sha, "code_files": len(source_code),
                                       "locked_artifacts": len(lock["artifact_sha256"]),
                                       "saved_final_status": final_summary["status"]}
        # Importing these modules defines functions/classes only; no stage is called.
        sys.path.insert(0, str(PIPELINE))
        from c3model.records import verify_collection, CURRENT, WIRE, CONTEXT
        print("Verifying accepted source seals and file hashes (no feature decoding)...", flush=True)
        info = verify_collection(source)
        admission = {"collection_id": info["collection_id"], "runs": len(info["runs"]),
                     "roles": info["role_counts"], "canonical_index_sha256": sha(source / "collection_complete.json")}
        require(admission == lock["collection"], "Imported collection does not match the locked experiment")
        require(read(artifacts / "admission.json") == admission, "Saved admission does not match imported collection")
        selection = read(artifacts / "selection.json")
        require(selection["source_admission"] == admission, "Selected models reference another collection")
        require(selection["code_sha256"] == source_code, "Selection code identity differs")
        totals = Counter()
        for run in info["runs"]:
            totals.update(run["label_counts"])
            text = (Path(run["folder"]) / "capture.log").read_text(encoding="utf8")
            drops = re.findall(r"(?m)^\s*(\d+) packets dropped by kernel\s*$", text)
            require(drops == ["0"], "Accepted capture has missing/nonzero drop footer: " + run["planned_run_id"])
        accepted_attempts = {Path(run["folder"]).name for run in info["runs"]}
        excluded = []
        for folder in sorted(source.glob("MX*")):
            if folder.is_dir() and folder.name not in accepted_attempts:
                disposition = folder / "attempt_disposition.json"
                excluded.append({"attempt": folder.name,
                                 "disposition": read(disposition) if disposition.exists() else "Not indexed; excluded"})
        result["dataset"] = dict(admission, label_counts=dict(totals), accepted_adus=sum(totals.values()),
                                 accepted_zero_drop_captures=len(info["runs"]),
                                 verified_artifact_count=info["verified_artifact_count"],
                                 excluded_attempts=excluded, final_payload_rows_decoded=False,
                                 source_bundle_id=info["source_bundle_id"],
                                 protocol_sha256=info["protocol_sha256"], roster_sha256=info["roster_sha256"])
        print("Source verified. Checking saved processed metadata and model files...", flush=True)
        with (artifacts / "actual_memberships.csv").open(encoding="utf-8-sig", newline="") as stream:
            memberships = list(csv.DictReader(stream))
        expected_members = {r["planned_run_id"]: r for r in info["runs"]}
        require(len(memberships) == 104 and len({r["planned_run_id"] for r in memberships}) == 104,
                "Saved membership count/uniqueness differs")
        for member in memberships:
            expected = expected_members[member["planned_run_id"]]
            for key in ("run_id", "related_group", "evaluation_role", "map", "values", "ordering", "timing"):
                require(member[key] == str(expected[key]), "Saved membership differs: " + member["planned_run_id"] + "/" + key)
        prepare = read(artifacts / "development/prepare_report.json")
        require(prepare["source_admission"] == admission, "Prepared data references another collection")
        import pyarrow.parquet as pq
        processed = {}
        for name in ("all_adus.parquet", "candidate_features.parquet", "routing_and_eligibility.parquet"):
            path = artifacts / "development" / name
            metadata = pq.ParquetFile(path)
            require(metadata.metadata.num_rows == prepare["adus"], "Processed row count differs: " + name)
            processed[name] = {"rows": metadata.metadata.num_rows, "columns": metadata.schema_arrow.names, "sha256": sha(path)}
        require(processed["candidate_features.parquet"]["columns"] == list(dict.fromkeys(CURRENT + WIRE + CONTEXT)),
                "Saved candidate feature column contract differs")
        with (artifacts / "development/labels.csv").open(encoding="utf-8-sig", newline="") as stream:
            labels = Counter(row["label"] for row in csv.DictReader(stream))
        require(dict(labels) == prepare["label_counts"] and sum(labels.values()) == prepare["adus"],
                "Saved label-table support differs from preparation report")
        result["processed_development"] = {"adus": prepare["adus"], "label_counts": dict(labels),
                                            "parquet_metadata": processed, "memberships_verified": len(memberships)}
        mirrors = {}
        for mirror in sorted((PIPELINE / "reports/locked_results").glob("*")):
            if not mirror.is_file():
                continue
            targets = [artifacts / mirror.name, artifacts / "development" / mirror.name, artifacts / "final" / mirror.name]
            present = [p for p in targets if p.is_file()]
            require(len(present) == 1, "Cannot identify archived report counterpart: " + mirror.name)
            require(sha(mirror) == sha(present[0]), "Archived report differs: " + mirror.name)
            mirrors[mirror.name] = sha(mirror)
        result["archived_report_mirrors_verified"] = mirrors
        import joblib
        from sklearn.utils.validation import check_is_fitted
        names = ["numpy", "pandas", "scikit-learn", "joblib", "pyarrow", "scipy", "threadpoolctl"]
        local_versions = {name: importlib.metadata.version(name) for name in names}
        require(local_versions["scikit-learn"] == selection["versions"]["scikit-learn"],
                "Use a compatible environment: scikit-learn differs from producer")
        result["environment"] = {"local_versions": local_versions, "producer_versions": selection["versions"],
                                 "differences": {name: {"producer": version, "local": local_versions.get(name)}
                                                 for name, version in selection["versions"].items()
                                                 if local_versions.get(name) != version}}
        models = {}
        require(set(selection["methods"]) == set(lock["methods"]), "Locked/selected method names differ")
        loaded_models = {}
        for name, columns in lock["methods"].items():
            path = artifacts / "models" / (name + ".joblib")
            require(sha(path) == selection["methods"][name]["model_sha256"], "Selected model SHA differs: " + name)
            require(columns == selection["methods"][name]["features"], "Selected input names differ: " + name)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                model = joblib.load(path)
            check_is_fitted(model)
            require(list(model.named_steps) == ["imputer", "rf"], "Unexpected saved model steps: " + name)
            check_is_fitted(model.named_steps["imputer"])
            check_is_fitted(model.named_steps["rf"])
            require(int(model.n_features_in_) == len(columns), "Saved input feature count differs: " + name)
            require(list(model.feature_names_in_) == columns, "Saved input feature names differ: " + name)
            require(set(model.classes_) == set(lock["classes"]), "Saved classes differ: " + name)
            classifier = model.named_steps["rf"]
            require(all(classifier.get_params()[key] == value for key, value in selection["methods"][name]["parameters"].items()),
                    "Saved classifier parameters differ: " + name)
            require(len(classifier.estimators_) == classifier.n_estimators, "Saved forest is incomplete: " + name)
            loaded_models[name] = model
            models[name] = {"status": "LOADED_FITTED_METADATA_VERIFIED", "sha256": sha(path),
                            "class": type(model).__name__, "input_features": len(columns),
                            "feature_names": columns, "classes": list(model.classes_),
                            "trees": len(classifier.estimators_),
                            "load_warnings": [str(item.message) for item in caught], "predictions_run": False}
            print(name + ": loaded; fitted metadata verified; no prediction or fitting", flush=True)
        result["models"] = models
        result["raw_metadata_unchanged"] = all(sha(source / name) == digest for name, digest in source_headers.items())
        require(result["raw_metadata_unchanged"], "Raw collection headers changed during verification")
        after = inventory(PIPELINE)
        require(after == before, "Imported pipeline/artifact bytes changed during verification")
        result["pipeline_and_artifacts_unchanged"] = True
        result["pipeline_file_sha256"] = before
        result["raw_collection_header_sha256"] = source_headers
        result["verifier_sha256"] = sha(Path(__file__))
        result["status"] = "VERIFIED_AND_FOUR_SAVED_MODELS_LOADED"
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
        result["pipeline_and_artifacts_unchanged"] = inventory(PIPELINE) == before
    result["exact_command_from_repository_root"] = (
        r".\.venv\Scripts\python.exe -B .\component3_local_verification\v1_20261025\verify_saved.py "
        r"--source component3_raw/collection --artifacts component3_model_pipeline/v1_20261025/artifacts")
    reports = HERE / "reports"
    reports.mkdir(exist_ok=True)
    target = reports / ("verification-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8] + ".json")
    with target.open("x", encoding="utf8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "report": str(target),
                      "dataset": {k: v for k, v in result.get("dataset", {}).items() if k not in ("excluded_attempts",)},
                      "models_loaded": list(result.get("models", {})), "errors": result["errors"]}, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=REPO / "component3_raw/collection")
    parser.add_argument("--artifacts", type=Path, default=PIPELINE / "artifacts")
    args = parser.parse_args()
    outcome = verify(args.source.resolve(), args.artifacts.resolve())
    raise SystemExit(0 if not outcome["errors"] else 1)

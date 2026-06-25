# -*- coding: utf-8 -*-
"""
AA-VAPT — Machine Learning engine
==================================
Two local, privacy-preserving ML capabilities for Nessus findings:

  1. FP Filter (supervised)   — learns from your own Confirmed / False-Positive
                                verdicts and predicts how likely a NEW finding is
                                a false positive.  RandomForest, class-balanced.
  2. Clustering (unsupervised) — groups similar findings (KMeans) so you can spot
                                "same misconfig across N hosts" patterns and
                                de-duplicate manual work.

Everything runs locally (scikit-learn).  Nothing leaves the machine.
Models are persisted with joblib under  backend/ai/models/.
"""
import os
import re
import math
import logging
import threading

log = logging.getLogger("aavapt.ml")

# scikit-learn is optional at import time so the backend still boots if it is
# not yet installed; endpoints report a clear "ml_unavailable" instead of 500.
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import KMeans
    from sklearn.model_selection import cross_val_score
    import joblib
    _ML_OK = True
    _ML_ERR = ""
except Exception as e:                      # pragma: no cover
    _ML_OK = False
    _ML_ERR = str(e)
    np = None

_LOCK = threading.Lock()
_MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(_MODELS_DIR, exist_ok=True)
_FP_PATH = os.path.join(_MODELS_DIR, "fp_model.joblib")

# ── Feature engineering ────────────────────────────────────────────────
_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0, "none": 0}
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 5985, 5986, 47001, 8100, 8300}
_ADMIN_PORTS = {22, 23, 445, 139, 3389, 135, 161, 1433, 3306, 5432, 1521}
# keyword flags that often correlate with FP-prone / low-signal findings
_KEYWORDS = [
    "ssl", "tls", "certificate", "http", "smb", "ssh", "rdp", "version",
    "disclosure", "weak", "deprecated", "expired", "self-signed", "default",
    "enumeration", "detection", "banner", "header", "timestamp", "traceroute",
]

# The feature order MUST stay stable between train and predict.
FEATURE_NAMES = (
    ["severity", "port", "port_is_web", "port_is_admin", "has_cve", "cve_count",
     "out_len", "name_len", "syn_len"]
    + ["kw_" + k.replace("-", "_") for k in _KEYWORDS]
)


def _num(v, default=0):
    try:
        return float(v)
    except Exception:
        return float(default)


def features(f: dict):
    """Turn one finding dict into a fixed-length numeric feature vector."""
    name = str(f.get("name", f.get("pluginName", "")) or "").lower()
    syn = str(f.get("synopsis", "") or "")
    out = str(f.get("pluginOutput", f.get("plugin_output", "")) or "")
    sev = _SEV.get(str(f.get("severity", "info")).lower(), 0)
    port = int(_num(re.sub(r"[^0-9]", "", str(f.get("port", "") or "")) or 0))
    cves = f.get("cves", []) or []
    if isinstance(cves, str):
        cves = [c for c in re.split(r"[,\s]+", cves) if c]
    row = [
        sev,
        min(port, 65535),
        1 if port in _WEB_PORTS else 0,
        1 if port in _ADMIN_PORTS else 0,
        1 if cves else 0,
        len(cves),
        math.log1p(len(out)),
        len(name),
        math.log1p(len(syn)),
    ]
    row += [1 if k in name else 0 for k in _KEYWORDS]
    return row


def _matrix(findings):
    return np.array([features(f) for f in findings], dtype=float)


def _label_of(f):
    """Map a finding's verdict/label to 1 = false-positive, 0 = true/confirmed.

    Accepts several shapes the frontend may send:
      label / verdict in {'fp','false-positive','confirmed','vuln','tp', ...}
      is_fp: bool
    Returns 1 (FP), 0 (real) or None (unlabeled -> skipped in training).
    """
    for key in ("label", "verdict", "is_fp", "fp"):
        if key in f and f[key] is not None:
            v = f[key]
            if isinstance(v, bool):
                return 1 if v else 0
            v = str(v).strip().lower()
            if v in ("fp", "false-positive", "false_positive", "falsepositive", "1", "true", "yes"):
                return 1
            if v in ("confirmed", "vuln", "vulnerable", "tp", "true-positive", "real", "0", "false", "no"):
                return 0
    return None


# ── Status ─────────────────────────────────────────────────────────────
def available():
    return _ML_OK


def status():
    info = {"ml_available": _ML_OK, "error": _ML_ERR if not _ML_OK else ""}
    if not _ML_OK:
        return info
    info["fp_trained"] = os.path.exists(_FP_PATH)
    if info["fp_trained"]:
        try:
            bundle = joblib.load(_FP_PATH)
            info["fp_samples"] = bundle.get("n_samples")
            info["fp_accuracy"] = bundle.get("accuracy")
            info["fp_classes"] = bundle.get("classes")
        except Exception as e:
            info["fp_trained"] = False
            info["error"] = str(e)
    return info


# ── 1) FP Filter — supervised ──────────────────────────────────────────
def train_fp(labeled_findings):
    """Train the false-positive classifier from labeled findings.

    Each finding needs a verdict/label (see _label_of).  Unlabeled ones are
    ignored.  Needs >= 8 labeled samples spanning both classes.
    """
    if not _ML_OK:
        return {"ok": False, "error": "scikit-learn not installed: " + _ML_ERR}
    X, y = [], []
    for f in labeled_findings or []:
        lab = _label_of(f)
        if lab is None:
            continue
        X.append(features(f))
        y.append(lab)
    n = len(y)
    classes = sorted(set(y))
    if n < 8:
        return {"ok": False, "error": f"Need >=8 labeled findings, got {n}. Verify more findings first.",
                "n_samples": n}
    if len(classes) < 2:
        return {"ok": False, "error": "Need BOTH confirmed and false-positive examples to learn (got only one class).",
                "n_samples": n, "classes": classes}
    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    clf = RandomForestClassifier(n_estimators=200, max_depth=None,
                                 class_weight="balanced", random_state=42, n_jobs=-1)
    # cross-validated accuracy estimate (honest, not train-on-train)
    try:
        cv = min(5, min(np.bincount(y)))   # folds <= smallest class size
        cv = max(2, cv)
        acc = float(np.mean(cross_val_score(clf, Xs, y, cv=cv, scoring="accuracy")))
    except Exception:
        acc = None
    clf.fit(Xs, y)
    importances = dict(sorted(
        zip(FEATURE_NAMES, [float(v) for v in clf.feature_importances_]),
        key=lambda kv: kv[1], reverse=True)[:8])
    with _LOCK:
        joblib.dump({"scaler": scaler, "clf": clf, "n_samples": n,
                     "accuracy": acc, "classes": classes,
                     "features": FEATURE_NAMES}, _FP_PATH)
    log.info("FP model trained: n=%d acc=%s", n, acc)
    return {"ok": True, "n_samples": n, "accuracy": acc, "classes": classes,
            "top_features": importances}


def predict_fp(findings):
    """Return per-finding false-positive probability (0..1) + a label.

    If no model is trained yet, falls back to a transparent heuristic so the
    feature is still useful on day one.
    """
    findings = findings or []
    if not findings:
        return {"ok": True, "trained": os.path.exists(_FP_PATH), "predictions": [],
                "note": "No findings to score — load a scan first."}
    if (not _ML_OK) or (not os.path.exists(_FP_PATH)):
        # heuristic stopgap (pure-Python, works even before scikit-learn is installed):
        # info severity + no CVE + 'detection/enumeration/banner' => higher FP odds
        out = []
        for f in findings:
            v = features(f)
            sev, has_cve = v[0], v[4]
            kw_idx = {k: FEATURE_NAMES.index("kw_" + k.replace("-", "_")) for k in
                      ("detection", "enumeration", "banner", "timestamp", "traceroute")}
            noise = sum(v[i] for i in kw_idx.values())
            score = 0.15
            if sev == 0:
                score += 0.35
            if not has_cve:
                score += 0.15
            if noise:
                score += 0.2
            score = min(score, 0.9)
            out.append({"idx": f.get("idx"), "fp_probability": round(score, 3),
                        "likely_fp": score >= 0.5, "source": "heuristic"})
        _note = ("scikit-learn not installed — heuristic only (run install.sh)."
                 if not _ML_OK else
                 "Model not trained yet — using heuristic. Train with your verdicts for real ML.")
        return {"ok": True, "trained": False, "source": "heuristic",
                "note": _note, "ml_available": _ML_OK, "predictions": out}
    bundle = joblib.load(_FP_PATH)
    scaler, clf = bundle["scaler"], bundle["clf"]
    X = scaler.transform(_matrix(findings))
    # probability of class '1' (false positive)
    classes = list(clf.classes_)
    proba = clf.predict_proba(X)
    fp_col = classes.index(1) if 1 in classes else 0
    out = []
    for i, f in enumerate(findings):
        p = float(proba[i][fp_col])
        out.append({"idx": f.get("idx"), "fp_probability": round(p, 3),
                    "likely_fp": p >= 0.5, "source": "model"})
    return {"ok": True, "trained": True, "source": "model",
            "accuracy": bundle.get("accuracy"), "predictions": out}


# ── 2) Clustering — unsupervised ───────────────────────────────────────
def cluster(findings, k=None):
    """Group similar findings with KMeans.  Returns per-finding cluster id and
    a human summary of each cluster (size, dominant severity, common ports/
    services, representative finding names, hosts touched)."""
    if not _ML_OK:
        return {"ok": False, "error": "scikit-learn not installed: " + _ML_ERR}
    findings = findings or []
    n = len(findings)
    if n < 4:
        return {"ok": False, "error": f"Need >=4 findings to cluster, got {n}."}
    X = _matrix(findings)
    Xs = StandardScaler().fit_transform(X)
    if not k or int(k) < 2:
        k = max(2, min(8, int(round(math.sqrt(n / 2)))))   # heuristic cluster count
    k = min(int(k), n)
    km = KMeans(n_clusters=k, n_init=10, random_state=42)
    labels = km.fit_predict(Xs)

    clusters = {}
    for i, f in enumerate(findings):
        cid = int(labels[i])
        c = clusters.setdefault(cid, {"id": cid, "indices": [], "names": [],
                                      "severities": [], "ports": [], "services": [],
                                      "hosts": set()})
        c["indices"].append(f.get("idx", i))
        c["names"].append(str(f.get("name", f.get("pluginName", "")) or ""))
        c["severities"].append(str(f.get("severity", "info")).lower())
        if f.get("port"):
            c["ports"].append(str(f.get("port")))
        if f.get("service") or f.get("svc_name"):
            c["services"].append(str(f.get("service", f.get("svc_name", ""))))
        for h in (f.get("hosts") or []):
            c["hosts"].add(h)
        ip = str(f.get("host", f.get("ip", "")) or "")
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip):
            c["hosts"].add(ip)

    def _top(lst, n=3):
        from collections import Counter
        return [w for w, _ in Counter([x for x in lst if x]).most_common(n)]

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    summaries = []
    for cid, c in sorted(clusters.items()):
        dom_sev = max(c["severities"], key=lambda s: sev_rank.get(s, 0)) if c["severities"] else "info"
        summaries.append({
            "id": cid,
            "size": len(c["indices"]),
            "dominant_severity": dom_sev,
            "common_ports": _top(c["ports"]),
            "common_services": _top(c["services"]),
            "sample_findings": _top(c["names"]),
            "hosts": sorted(c["hosts"]),
            "host_count": len(c["hosts"]),
            "indices": c["indices"],
        })
    summaries.sort(key=lambda s: (sev_rank.get(s["dominant_severity"], 0), s["size"]), reverse=True)
    return {"ok": True, "k": k, "n": n,
            "assignments": [int(l) for l in labels],
            "clusters": summaries}


# ── 3) Risk Ranking — explainable priority score (no training needed) ──
# Pure-Python: works always, even without scikit-learn. The frontend passes the
# signals it already knows (severity, cvss, exploit-available, CISA-KEV, EPSS,
# asset criticality); we fuse them into a 0-100 "fix this first" score + reasons.
_SEV_PTS = {"critical": 25, "high": 18, "medium": 10, "low": 4, "info": 1, "informational": 1, "none": 1}


def risk_rank(findings, asset_weights=None):
    """Score & sort findings by remediation priority.

    Per-finding optional signals (any subset):
      severity        : critical/high/medium/low/info
      cvss            : float 0-10        (base score)
      exploit / has_exploit / msf / edb : bool  -> public exploit exists
      kev / cisa_kev  : bool             -> actively exploited in the wild
      epss            : float 0-1        -> exploit-prediction score
      cves            : list             -> +small bump if CVEs assigned
    asset_weights : optional {ip: multiplier} to boost critical assets (1.0 default).
    """
    findings = findings or []
    asset_weights = asset_weights or {}
    ranked = []
    for i, f in enumerate(findings):
        sev = str(f.get("severity", "info")).lower()
        score = float(_SEV_PTS.get(sev, 1))          # 1-25
        reasons = ["severity=" + sev]

        cvss = f.get("cvss", f.get("cvss_score"))
        try:
            cvss = float(cvss)
        except (TypeError, ValueError):
            cvss = None
        if cvss is not None:
            score += min(max(cvss, 0), 10) * 2.0     # 0-20
            reasons.append("CVSS=%.1f" % cvss)

        has_exploit = bool(f.get("exploit") or f.get("has_exploit") or f.get("msf") or f.get("edb"))
        if has_exploit:
            score += 25
            reasons.append("public exploit available")

        kev = bool(f.get("kev") or f.get("cisa_kev"))
        if kev:
            score += 20
            reasons.append("CISA KEV — actively exploited")

        epss = f.get("epss")
        try:
            epss = float(epss)
            if epss > 1:           # if passed as percentage
                epss /= 100.0
            score += min(max(epss, 0), 1) * 10       # 0-10
            reasons.append("EPSS=%.2f" % epss)
        except (TypeError, ValueError):
            pass

        cves = f.get("cves") or []
        if cves:
            score += 3
            reasons.append("%d CVE(s)" % len(cves))

        # asset criticality multiplier (boost important machines)
        mult = 1.0
        hosts = f.get("hosts") or []
        ip = str(f.get("host", f.get("ip", "")) or "")
        if ip and ip not in hosts:
            hosts = hosts + [ip]
        for h in hosts:
            if h in asset_weights:
                mult = max(mult, float(asset_weights[h] or 1.0))
        if mult != 1.0:
            score *= mult
            reasons.append("asset x%.1f" % mult)

        score = round(min(score, 100.0), 1)
        if score >= 75:
            band = "Critical"
        elif score >= 50:
            band = "High"
        elif score >= 25:
            band = "Medium"
        else:
            band = "Low"

        ranked.append({
            "idx": f.get("idx", i),
            "name": f.get("name", f.get("pluginName", "")),
            "hosts": sorted(set(hosts)),
            "severity": sev,
            "risk_score": score,
            "priority": band,
            "reasons": reasons,
        })

    ranked.sort(key=lambda r: r["risk_score"], reverse=True)
    for rank, r in enumerate(ranked, 1):
        r["rank"] = rank
    bands = {}
    for r in ranked:
        bands[r["priority"]] = bands.get(r["priority"], 0) + 1
    return {"ok": True, "n": len(ranked), "bands": bands, "ranked": ranked}

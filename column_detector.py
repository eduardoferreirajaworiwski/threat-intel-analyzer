"""
column_detector.py
------------------
Auto-detects semantic types for arbitrary CSV columns.
Supports: IPv4, timestamps, network ports, firewall actions.

Returns confidence scores and name-hint bonuses so the UI can show
how certain the detection is and let the user override it.
"""

import re
import ipaddress
from datetime import datetime
from typing import Optional

import pandas as pd

# ── Constants ────────────────────────────────────────────────────────────────

_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
    "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y",
]

_ACTION_KEYWORDS = frozenset({
    "allow", "deny", "drop", "accept", "reject", "blocked",
    "passed", "permit", "block", "pass", "forward", "discard",
})

# Column name hints per semantic type (lowercase)
_HINTS = {
    "ip":        {"ip", "src_ip", "source_ip", "ip_address", "srcip", "sourceip",
                  "client_ip", "remote_ip", "attacker_ip", "origin", "source", "src"},
    "timestamp": {"timestamp", "time", "datetime", "date", "ts", "event_time",
                  "log_time", "created_at", "occurred_at", "dt"},
    "port":      {"port", "dst_port", "destination_port", "dstport", "dest_port",
                  "target_port", "remote_port", "sport", "dport"},
    "action":    {"action", "verdict", "decision", "result", "status",
                  "firewall_action", "disposition", "policy"},
}

# Canonical names used throughout the app
CANONICAL = {
    "ip":        "source_ip",
    "timestamp": "timestamp",
    "port":      "destination_port",
    "action":    "action",
}


# ── Validators ───────────────────────────────────────────────────────────────

def is_valid_ip(value: str) -> bool:
    """True if string is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """True if IP is in a private/reserved range (RFC 1918, loopback, link-local)."""
    try:
        return ipaddress.ip_address(str(ip_str).strip()).is_private
    except ValueError:
        return False


def is_port(value) -> bool:
    """True if value is a valid TCP/UDP port number (1–65535)."""
    try:
        return 1 <= int(float(str(value))) <= 65535
    except (ValueError, TypeError):
        return False


def is_timestamp(value: str) -> bool:
    """True if string parses as a known timestamp format."""
    s = str(value).strip()
    for fmt in _TS_FORMATS:
        try:
            datetime.strptime(s, fmt)
            return True
        except ValueError:
            continue
    return False


def is_action(value: str) -> bool:
    """True if string is a known firewall/IDS action keyword."""
    return str(value).strip().lower() in _ACTION_KEYWORDS


# ── Core Detection ───────────────────────────────────────────────────────────

def detect_column_type(series: pd.Series) -> tuple[str, float]:
    """
    Infer the semantic type of a DataFrame column from sampled values.

    Returns:
        (type_str, confidence) — type_str ∈ {'ip','timestamp','port','action','unknown'}
        confidence ∈ [0.0, 1.0]
    """
    sample = series.dropna().head(30).astype(str)
    if len(sample) == 0:
        return ("unknown", 0.0)

    ip_score  = sample.apply(is_valid_ip).mean()
    ts_score  = sample.apply(is_timestamp).mean()
    act_score = sample.apply(is_action).mean()

    # Ports: numeric + bounded cardinality
    port_score = 0.0
    if series.nunique() <= 200:
        port_score = sample.apply(is_port).mean()
        # Penalise if many values exceed port range (looks like generic int column)
        over_range = sample.apply(
            lambda x: not is_port(x) and x.isdigit()
        ).mean()
        port_score *= max(0.0, 1.0 - over_range)

    scores = {"ip": ip_score, "timestamp": ts_score,
              "port": port_score, "action": act_score}
    best, conf = max(scores.items(), key=lambda kv: kv[1])

    if conf < 0.45:
        return ("unknown", round(conf, 2))
    return (best, round(conf, 2))


def auto_map_columns(df: pd.DataFrame) -> tuple[dict, dict]:
    """
    Map DataFrame columns to canonical semantic names.

    Returns:
        mapping  — {canonical_name: actual_column_name}  e.g. {'source_ip': 'src_ip'}
        col_info — {actual_column_name: (detected_type, confidence)}
    """
    col_info: dict[str, tuple[str, float]] = {}

    for col in df.columns:
        ctype, conf = detect_column_type(df[col])

        # Boost confidence when column name itself is a recognisable hint
        col_lower = col.lower().strip()
        for semantic, hints in _HINTS.items():
            if col_lower in hints:
                if ctype == semantic:
                    conf = min(1.0, conf + 0.30)
                elif conf < 0.40:
                    # Name is strong hint, value scan was inconclusive → defer to name
                    ctype, conf = semantic, 0.55
                break

        col_info[col] = (ctype, round(conf, 2))

    # Assign canonical names — take highest confidence per type
    mapping: dict[str, str] = {}
    best_conf: dict[str, float] = {}

    for col, (ctype, conf) in sorted(col_info.items(), key=lambda x: -x[1][1]):
        canon = CANONICAL.get(ctype)
        if canon and (canon not in mapping or conf > best_conf[canon]):
            mapping[canon] = col
            best_conf[canon] = conf

    return mapping, col_info


def normalize_dataframe(df: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    """
    Return a copy of df with columns renamed to canonical names.
    Missing canonical columns are added as NaN.
    """
    rename = {actual: canon for canon, actual in mapping.items() if actual in df.columns}
    df_norm = df.rename(columns=rename).copy()

    for canon in CANONICAL.values():
        if canon not in df_norm.columns:
            df_norm[canon] = None

    return df_norm


def validate_dataframe(df: pd.DataFrame, mapping: dict) -> list[str]:
    """
    Basic security/sanity checks on the uploaded data.
    Returns a list of warning strings (empty = OK).
    """
    warnings = []

    if len(df) == 0:
        warnings.append("O arquivo CSV está vazio.")
        return warnings

    if len(df) > 100_000:
        warnings.append(f"Arquivo muito grande ({len(df):,} linhas). Análise pode ser lenta.")

    ip_col = mapping.get("source_ip")
    if ip_col and ip_col in df.columns:
        sample_ips = df[ip_col].dropna().head(50).astype(str)
        invalid = sample_ips[~sample_ips.apply(is_valid_ip)]
        if len(invalid) > len(sample_ips) * 0.3:
            warnings.append(
                f"Coluna '{ip_col}' contém muitos valores que não parecem IPs válidos."
            )

    return warnings

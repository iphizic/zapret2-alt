#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import shlex
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


# ----------------------------
# Tables
# ----------------------------

DROP_PREFIXES = (
    "--wf-",
    "--ssid-filter",
    "--nlm-filter",
    "--nlm-list",
)

# Hostlists are intentionally stripped for target nfqws2 configs.
# The resulting strategy keeps protocol/L7 filters and desync logic only.
HOSTLIST_PREFIXES = (
    "--ipset",
    "--ipset-exclude",
    "--hostlist",
    "--hostlist-exclude",
    "--hostlist-auto",
    "--hostlist-auto-fail-threshold",
    "--hostlist-auto-fail-time",
    "--hostlist-auto-retrans-threshold",
    "--hostlist-auto-retrans-reset",
    "--hostlist-auto-retrans-maxseq",
    "--hostlist-auto-incoming-maxseq",
    "--hostlist-auto-udp-out",
    "--hostlist-auto-udp-in",
    "--hostlist-auto-debug",
)

NFQWS2_GLOBAL_PREFIXES = (
    "--debug",
    "--version",
    "--dry-run",
    "--comment",
    "--intercept",
    "--daemon",
    "--chdir",
    "--pidfile",
    "--ctrack-timeouts",
    "--ctrack-disable",
    "--payload-disable",
    "--server",
    "--ipcache-lifetime",
    "--ipcache-hostname",
    "--reasm-disable",
    "--writeable",
    "--lua-init",
    "--lua-gc",
    "--qnum",
    "--user",
    "--uid",
    "--bind-fix4",
    "--bind-fix6",
    "--fwmark",
)

NFQWS2_PROFILE_PREFIXES = (
    "--new",
    "--skip",
    "--name",
    "--template",
    "--cookie",
    "--import",
    "--filter-l3",
    "--filter-tcp",
    "--filter-udp",
    "--filter-icmp",
    "--filter-ipp",
    "--filter-l7",
    "--ipset",
    "--ipset-ip",
    "--ipset-exclude",
    "--ipset-exclude-ip",
    "--hostlist",
    "--hostlist-domains",
    "--hostlist-exclude",
    "--hostlist-exclude-domains",
    "--hostlist-auto",
    "--hostlist-auto-fail-threshold",
    "--hostlist-auto-fail-time",
    "--hostlist-auto-retrans-threshold",
    "--hostlist-auto-retrans-reset",
    "--hostlist-auto-retrans-maxseq",
    "--hostlist-auto-incoming-maxseq",
    "--hostlist-auto-udp-out",
    "--hostlist-auto-udp-in",
    "--hostlist-auto-debug",
    "--payload",
    "--out-range",
    "--in-range",
    "--filter-ssid",
    # Flowseal/zapret1 option. Keep explicit, do not silently lose it.
    "--ip-id",
)

OLD_DPI_PREFIX = "--dpi-desync"

MODE_MAP = {
    "fake": "fake",
    "rst": "rst",
    "multisplit": "multisplit",
    "multidisorder": "multidisorder",
    "multidisorder-legacy": "multidisorder_legacy",
    "multidisorder_legacy": "multidisorder_legacy",
    "fakedsplit": "fakedsplit",
    "fakeddisorder": "fakeddisorder",
    "hostfakesplit": "hostfakesplit",
    "tcpseg": "tcpseg",
    "oob": "oob",
    "udplen": "udplen",
    "syndata": "syndata",
}

FOOLING_DIRECT_MAP = {
    "badsum": "badsum",
    "md5sig": "tcp_md5",
    "tcp-md5": "tcp_md5",
    "hopbyhop": "ip6_hopbyhop",
    "hopbyhop2": "ip6_hopbyhop2",
    "destopt": "ip6_destopt",
    "destopt2": "ip6_destopt2",
    "ipfrag1": "ipfrag",
    "ipfrag2": "ipfrag",
    "ts": "tcp_ts_up",
    "datanoack": "tcp_flags_unset=ACK",
}

PAYLOAD_BY_FAKE_OPT = {
    "--dpi-desync-fake-tls": "tls_client_hello",
    "--dpi-desync-fake-quic": "quic_initial",
    "--dpi-desync-fake-http": "http_req",
    "--dpi-desync-fake-unknown": "unknown",
    "--dpi-desync-fake-unknown-udp": "unknown_udp",
    # nfqws2 may not have dedicated payload names for these.
    # They are selected mainly by --filter-l7.
    "--dpi-desync-fake-discord": "discord",
    "--dpi-desync-fake-stun": "stun",
}

L7_BY_PAYLOAD = {
    "tls_client_hello": "tls",
    "http_req": "http",
    "quic_initial": "quic",
    "dtls_client_hello": "dtls",
    "discord": "discord",
    "stun": "stun",
}

DEFAULT_BLOB_BY_PAYLOAD = {
    "tls_client_hello": "fake_default_tls",
    "http_req": "fake_default_http",
    "quic_initial": "fake_default_quic",
}

SUPPORTED_DPI_OPTIONS = {
    "--dpi-desync",
    "--dpi-desync-fooling",
    "--dpi-desync-badseq-increment",
    "--dpi-desync-badack-increment",
    "--dpi-desync-ttl",
    "--dpi-desync-autottl",
    "--dpi-desync-ipfrag-pos-tcp",
    "--dpi-desync-ipfrag-pos-udp",
    "--dpi-desync-repeats",
    "--dpi-desync-cutoff",
    "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-udplen-increment",
    "--dpi-desync-udplen-min",
    "--dpi-desync-udplen-max",
    "--dpi-desync-udplen-pattern",
    "--dpi-desync-hostfakesplit-mod",
    "--dpi-desync-hostfakesplit-midhost",
    "--dpi-desync-hostfakesplit-disorder",
    "--dpi-desync-fake-tls-mod",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-any-protocol",
}

BATCH_VAR_RE = re.compile(r"%[A-Za-z0-9_]+%|![A-Za-z0-9_]+!")


# ----------------------------
# Data structs
# ----------------------------

@dataclass
class BlobStore:
    blobs: list[str] = field(default_factory=list)
    counter: int = 0
    by_value: dict[str, str] = field(default_factory=dict)

    def add(self, prefix: str, value: str) -> str:
        value = dequote(value)
        key = value

        # Do not emit duplicate --blob entries for the same file/hex payload.
        # nfqws2 can reuse one blob name across several --lua-desync instances.
        if key in self.by_value:
            return self.by_value[key]

        self.counter += 1
        name = f"{prefix}_{self.counter}"
        self.by_value[key] = name

        if value.startswith("0x"):
            self.blobs.append(f"--blob={name}:{value}")
        else:
            self.blobs.append(f"--blob={name}:@{value}")

        return name


@dataclass
class Profile:
    prefix_new: str | None = None
    globals_or_filters: list[str] = field(default_factory=list)
    dpi: dict[str, list[str]] = field(default_factory=dict)
    old_http_mods: dict[str, str] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)


# ----------------------------
# Parsing helpers
# ----------------------------

def dequote(s: str) -> str:
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def normalize_key_value_quotes(token: str) -> str:
    if token.startswith("--") and "=" in token:
        k, v = token.split("=", 1)
        return f"{k}={dequote(v)}"
    return dequote(token)


def shell_join(tokens: list[str]) -> str:
    return " ".join(shlex.quote(x) for x in tokens)


def key_val(token: str) -> tuple[str, str | None]:
    if not token.startswith("--"):
        return token, None
    if "=" in token:
        k, v = token.split("=", 1)
        return k, v
    return token, None


def is_prefix(key: str, prefixes: tuple[str, ...]) -> bool:
    return any(
        key == p or key.startswith(p + "=") or key.startswith(p)
        for p in prefixes
    )


def has_unexpanded_batch_var(token: str) -> bool:
    return bool(BATCH_VAR_RE.search(token))


def strip_batch_vars_from_csv(value: str) -> str:
    return ",".join(
        x.strip()
        for x in value.split(",")
        if x.strip() and not has_unexpanded_batch_var(x)
    )


def sanitized_port_filter_token(key: str, value: str | None) -> str | None:
    if value is None:
        return None

    mapped_key = {
        "--wf-tcp": "--filter-tcp",
        "--wf-udp": "--filter-udp",
        "--filter-tcp": "--filter-tcp",
        "--filter-udp": "--filter-udp",
    }.get(key)

    if not mapped_key:
        return None

    value = strip_batch_vars_from_csv(value)
    if not value:
        return None

    return f"{mapped_key}={value}"


def unescape_batch_carets(s: str) -> str:
    # After line-continuation carets are consumed, all remaining caret escapes
    # should be literalized: ^! -> !, ^X -> X. Drop a lone caret if present.
    return re.sub(r"\^(.)", r"\1", s).replace("^", "")


def normalize_bat(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    buf = ""

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        low = line.lower()
        if low.startswith("rem ") or low.startswith("::"):
            continue

        if line.endswith("^"):
            # This caret is only a line continuation marker.
            buf += line[:-1].strip() + " "
        else:
            buf += line
            out.append(unescape_batch_carets(buf))
            buf = ""

    if buf:
        out.append(unescape_batch_carets(buf))

    return "\n".join(out)


def parse_bat_vars(text: str, root: str) -> dict[str, str]:
    vars_ = {
        "~dp0": root.rstrip("/\\") + "/",
        "CD": ".",
    }

    for line in normalize_bat(text).splitlines():
        m = re.match(r'(?i)\s*set\s+"?([A-Za-z0-9_]+)\s*=\s*([^"]*)"?\s*$', line)
        if not m:
            m = re.match(r'(?i)\s*set\s+([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$', line)

        if m:
            k = m.group(1)
            v = m.group(2).strip()
            vars_[k] = v

    return vars_


def expand_vars(s: str, vars_: dict[str, str], lists_dir: str, bin_dir: str) -> str:
    vars2 = dict(vars_)
    vars2["BIN"] = bin_dir.rstrip("/") + "/"
    vars2["LISTS"] = lists_dir.rstrip("/") + "/"

    def repl_percent(m):
        name = m.group(1)
        return vars2.get(name, m.group(0))

    def repl_bang(m):
        name = m.group(1)
        return vars2.get(name, m.group(0))

    s = re.sub(r"%([A-Za-z0-9_]+)%", repl_percent, s)
    s = re.sub(r"!([A-Za-z0-9_]+)!", repl_bang, s)
    s = s.replace("%~dp0", vars2.get("~dp0", ""))

    # Windows paths -> Linux-style paths.
    s = s.replace("\\", "/")

    return s


def extract_winws_commands(text: str) -> list[str]:
    normalized = normalize_bat(text)
    commands = []

    for line in normalized.splitlines():
        if re.search(r'(?i)\bwinws(?:2)?\.exe\b', line):
            cmd = re.sub(
                r'(?i)^.*?(?:"[^"]*winws(?:2)?\.exe"|[^\s"]*winws(?:2)?\.exe)\s+',
                "",
                line,
                count=1,
            )

            cmd = re.split(
                r'(?i)\s+(?:pause|goto|exit|taskkill|sc\s+|net\s+)',
                cmd,
                maxsplit=1,
            )[0].strip()

            commands.append(cmd)

    if not commands:
        raise SystemExit("Не найден запуск winws.exe/winws2.exe")

    return commands


def tokenize_command(cmd: str) -> list[str]:
    # posix=False better survives Windows paths and batch-like quoting.
    raw = shlex.split(cmd, posix=False)
    return [normalize_key_value_quotes(x.strip()) for x in raw if x.strip()]


def split_profiles(tokens: list[str]) -> list[Profile]:
    profiles: list[Profile] = [Profile()]

    for t in tokens:
        k, _ = key_val(t)

        if k == "--new" or k.startswith("--new="):
            profiles.append(Profile(prefix_new=t))
            continue

        profiles[-1].globals_or_filters.append(t)

    return [p for p in profiles if p.prefix_new or p.globals_or_filters]


def add_dpi(profile: Profile, key: str, val: str):
    profile.dpi.setdefault(key, []).append(val)


def dpi_values(profile: Profile, key: str) -> list[str]:
    return profile.dpi.get(key, [])


def dpi_first(profile: Profile, key: str, default=None):
    vals = dpi_values(profile, key)
    return vals[0] if vals else default


def dpi_last(profile: Profile, key: str, default=None):
    vals = dpi_values(profile, key)
    return vals[-1] if vals else default


def classify_profile(profile: Profile) -> Profile:
    kept = []

    for t in profile.globals_or_filters:
        t = normalize_key_value_quotes(t)
        k, v = key_val(t)

        port_filter = sanitized_port_filter_token(k, v)
        if port_filter:
            kept.append(port_filter)
            continue

        if is_prefix(k, DROP_PREFIXES):
            profile.dropped.append(t)
            continue

        if is_prefix(k, HOSTLIST_PREFIXES):
            profile.dropped.append(t)
            continue

        # Remove any still-unexpanded real batch variable even if key itself is valid.
        if has_unexpanded_batch_var(t):
            profile.dropped.append(t)
            continue

        if k.startswith(OLD_DPI_PREFIX):
            add_dpi(profile, k, "" if v is None else v)
            continue

        # Old HTTP modifiers from zapret1/winws.
        if k in ("--hostcase", "--domcase", "--hostspell", "--methodeol", "--unixeol"):
            profile.old_http_mods[k] = "" if v is None else v
            continue

        if is_prefix(k, NFQWS2_GLOBAL_PREFIXES) or is_prefix(k, NFQWS2_PROFILE_PREFIXES):
            kept.append(t)
            continue

        profile.unknown.append(t)

    profile.globals_or_filters = kept
    return profile


# ----------------------------
# Inference helpers
# ----------------------------

def has_option(tokens: list[str], key: str) -> bool:
    return any(x == key or x.startswith(key + "=") for x in tokens)


def option_value(tokens: list[str], key: str) -> str | None:
    for x in tokens:
        k, v = key_val(x)
        if k == key:
            return v
    return None


def replace_option_value(tokens: list[str], key: str, value: str) -> list[str]:
    out = []
    replaced = False
    for x in tokens:
        k, _ = key_val(x)
        if k == key:
            if not replaced:
                out.append(f"{key}={value}")
                replaced = True
            continue
        out.append(x)
    if not replaced:
        out.append(f"{key}={value}")
    return out


def append_filter_l7_if_missing(filters: list[str], l7: str | None, autofilter_l7: bool):
    if not autofilter_l7 or not l7:
        return
    if has_option(filters, "--filter-l7"):
        return
    filters.append(f"--filter-l7={l7}")


def infer_payload(profile: Profile) -> str | None:
    # If --payload already exists, do not override it.
    existing_payload = option_value(profile.globals_or_filters, "--payload")
    if existing_payload:
        return None

    # 1. Explicit fake-*.
    for opt, payload in PAYLOAD_BY_FAKE_OPT.items():
        if dpi_values(profile, opt):
            # unknown/discord/stun are blob hints, not nfqws2 payload classifiers.
            if payload in ("unknown", "unknown_udp", "discord", "stun"):
                continue
            return payload

    # 2. By filter-l7.
    l7 = option_value(profile.globals_or_filters, "--filter-l7")
    if l7:
        vals = set(x.strip() for x in l7.split(","))
        if "tls" in vals:
            return "tls_client_hello"
        if "http" in vals:
            return "http_req"
        if "quic" in vals:
            return "quic_initial"
        if "dtls" in vals:
            return "dtls_client_hello"

    # 3. By ports.
    tcp = option_value(profile.globals_or_filters, "--filter-tcp")
    udp = option_value(profile.globals_or_filters, "--filter-udp")

    if tcp and "443" in tcp:
        return "tls_client_hello"
    if tcp and "80" in tcp:
        return "http_req"
    if udp and "443" in udp:
        return "quic_initial"

    return None


def infer_blob_payload(profile: Profile, payload_filter: str | None) -> str | None:
    for opt, payload in PAYLOAD_BY_FAKE_OPT.items():
        if dpi_values(profile, opt):
            return payload
    return payload_filter


def blob_prefix_by_payload(payload: str) -> str:
    return {
        "tls_client_hello": "fake_tls",
        "http_req": "fake_http",
        "quic_initial": "fake_quic",
        "unknown": "fake_unknown",
        "unknown_udp": "fake_unknown_udp",
        "discord": "fake_discord",
        "stun": "fake_stun",
    }.get(payload, "blob")


def l7_values(profile: Profile) -> set[str]:
    l7 = option_value(profile.globals_or_filters, "--filter-l7") or ""
    return {x.strip() for x in l7.split(",") if x.strip()}


def fake_blob_for_payload(
    profile: Profile,
    payload: str | None,
    blobs: BlobStore,
    prefer_defaults: bool,
    warnings: list[str] | None = None,
) -> str | None:
    l7s = l7_values(profile)

    # L7-specific Flowseal fake blobs.
    if "discord" in l7s and dpi_values(profile, "--dpi-desync-fake-discord"):
        vals = dpi_values(profile, "--dpi-desync-fake-discord")
        return blobs.add("fake_discord", vals[-1])

    if "stun" in l7s and dpi_values(profile, "--dpi-desync-fake-stun"):
        vals = dpi_values(profile, "--dpi-desync-fake-stun")
        return blobs.add("fake_stun", vals[-1])

    if not payload:
        return None

    if payload == "unknown_udp" and dpi_values(profile, "--dpi-desync-fake-unknown-udp"):
        vals = dpi_values(profile, "--dpi-desync-fake-unknown-udp")
        return blobs.add("fake_unknown_udp", vals[-1])

    # Useful if Linux does not have files from Windows Flowseal bundle.
    if prefer_defaults and payload in DEFAULT_BLOB_BY_PAYLOAD:
        return DEFAULT_BLOB_BY_PAYLOAD[payload]

    for opt, p in PAYLOAD_BY_FAKE_OPT.items():
        if p != payload:
            continue
        vals = dpi_values(profile, opt)
        if vals:
            return blobs.add(blob_prefix_by_payload(payload), vals[-1])

    # If fake is present without concrete file.
    if payload in DEFAULT_BLOB_BY_PAYLOAD:
        return DEFAULT_BLOB_BY_PAYLOAD[payload]

    if warnings and payload in ("discord", "stun", "unknown_udp"):
        warnings.append(f"missing-blob-for-payload:{payload}")

    return None


def parse_modes(profile: Profile) -> list[str]:
    raw = dpi_last(profile, "--dpi-desync", "") or ""
    modes = []

    for x in raw.split(","):
        x = x.strip()
        if not x:
            continue
        modes.append(MODE_MAP.get(x, x))

    return modes


def list_csv(v: str | None) -> list[str]:
    if not v:
        return []
    return [x.strip() for x in v.split(",") if x.strip()]


def clone_profile_for_l7(profile: Profile, l7: str) -> Profile:
    return Profile(
        prefix_new=profile.prefix_new,
        globals_or_filters=replace_option_value(profile.globals_or_filters, "--filter-l7", l7),
        dpi={k: list(v) for k, v in profile.dpi.items()},
        old_http_mods=dict(profile.old_http_mods),
        unknown=list(profile.unknown),
        dropped=list(profile.dropped),
    )


def split_l7_specific_profiles(profile: Profile, warnings: list[str]) -> list[Profile]:
    l7s = l7_values(profile)
    has_discord = "discord" in l7s and dpi_values(profile, "--dpi-desync-fake-discord")
    has_stun = "stun" in l7s and dpi_values(profile, "--dpi-desync-fake-stun")

    if has_discord and has_stun:
        return [clone_profile_for_l7(profile, "discord"), clone_profile_for_l7(profile, "stun")]

    if has_discord and dpi_values(profile, "--dpi-desync-fake-stun"):
        warnings.append("multiple-l7-fake-blobs:using-discord-blob-stun-left-unused")
    if has_stun and dpi_values(profile, "--dpi-desync-fake-discord"):
        warnings.append("multiple-l7-fake-blobs:using-stun-blob-discord-left-unused")

    return [profile]


# ----------------------------
# Conversion
# ----------------------------

def add_standard_fooling_args(profile: Profile, args: list[str], warnings: list[str]):
    fooling = list_csv(dpi_last(profile, "--dpi-desync-fooling"))

    for f in fooling:
        if f == "badseq":
            inc = dpi_last(profile, "--dpi-desync-badseq-increment", "-10000")
            args.append(f"tcp_seq={inc}")

        elif f == "badack":
            inc = dpi_last(profile, "--dpi-desync-badack-increment", "-66000")
            args.append(f"tcp_ack={inc}")

        elif f in FOOLING_DIRECT_MAP:
            args.append(FOOLING_DIRECT_MAP[f])

        else:
            warnings.append(f"unknown-fooling:{f}")

    ttl = dpi_last(profile, "--dpi-desync-ttl")
    if ttl:
        args.append(f"ip_ttl={ttl}")
        args.append(f"ip6_ttl={ttl}")

    autottl = dpi_last(profile, "--dpi-desync-autottl")
    if autottl:
        args.append(f"ip_autottl={autottl}")
        args.append(f"ip6_autottl={autottl}")

    v = dpi_last(profile, "--dpi-desync-ipfrag-pos-tcp")
    if v:
        args.append(f"ipfrag_pos_tcp={v}")

    v = dpi_last(profile, "--dpi-desync-ipfrag-pos-udp")
    if v:
        args.append(f"ipfrag_pos_udp={v}")

    repeats = dpi_last(profile, "--dpi-desync-repeats")
    if repeats:
        args.append(f"repeats={repeats}")

    cutoff = dpi_last(profile, "--dpi-desync-cutoff")
    if cutoff:
        # In nfqws2 this is usually better manually ported to --out-range/--in-range.
        warnings.append(f"manual-cutoff:{cutoff}")


def add_split_args(profile: Profile, args: list[str], blobs: BlobStore):
    v = dpi_last(profile, "--dpi-desync-split-pos")
    if v:
        args.append(f"pos={v}")

    v = dpi_last(profile, "--dpi-desync-split-seqovl")
    if v:
        args.append(f"seqovl={v}")

    v = dpi_last(profile, "--dpi-desync-split-seqovl-pattern")
    if v:
        name = blobs.add("seqovl_pattern", v)
        args.append(f"seqovl_pattern={name}")


def add_fake_split_pattern(profile: Profile, args: list[str], blobs: BlobStore):
    val = dpi_last(profile, "--dpi-desync-fakedsplit-pattern")
    if val:
        name = blobs.add("fake_pattern", val)
        args.append(f"pattern={name}")


def add_udplen_args(profile: Profile, args: list[str], blobs: BlobStore):
    mapping = {
        "--dpi-desync-udplen-increment": "increment",
        "--dpi-desync-udplen-min": "min",
        "--dpi-desync-udplen-max": "max",
    }

    for old, new in mapping.items():
        v = dpi_last(profile, old)
        if v:
            args.append(f"{new}={v}")

    v = dpi_last(profile, "--dpi-desync-udplen-pattern")
    if v:
        name = blobs.add("udplen_pattern", v)
        args.append(f"pattern={name}")


def add_hostfakesplit_args(profile: Profile, args: list[str]):
    mapping = {
        "--dpi-desync-hostfakesplit-mod": "host",
        "--dpi-desync-hostfakesplit-midhost": "midhost",
        "--dpi-desync-hostfakesplit-disorder": "disorder_after",
    }

    for old, new in mapping.items():
        v = dpi_last(profile, old)
        if v:
            args.append(f"{new}={v}")


def add_tls_mod(profile: Profile, args: list[str]):
    val = dpi_last(profile, "--dpi-desync-fake-tls-mod")
    if val:
        args.append(f"tls_mod={val}")


def build_lua_instances(
    profile: Profile,
    blobs: BlobStore,
    prefer_defaults: bool,
    warnings: list[str],
) -> tuple[list[str], str | None]:
    modes = parse_modes(profile)
    if not modes:
        return [], None

    payload = infer_payload(profile)
    blob_payload = infer_blob_payload(profile, payload)
    fake_blob = fake_blob_for_payload(
        profile,
        blob_payload,
        blobs,
        prefer_defaults=prefer_defaults,
        warnings=warnings,
    )

    out = []

    for mode in modes:
        args = []

        add_standard_fooling_args(profile, args, warnings)

        if mode in (
            "multisplit",
            "multidisorder",
            "multidisorder_legacy",
            "fakedsplit",
            "fakeddisorder",
            "tcpseg",
        ):
            add_split_args(profile, args, blobs)

        if mode in ("fakedsplit", "fakeddisorder"):
            add_fake_split_pattern(profile, args, blobs)

        if mode == "udplen":
            add_udplen_args(profile, args, blobs)

        if mode == "hostfakesplit":
            add_hostfakesplit_args(profile, args)

        if mode in (
            "fake",
            "syndata",
            "multisplit",
            "multidisorder",
            "multidisorder_legacy",
            "fakedsplit",
            "fakeddisorder",
            "hostfakesplit",
            "tcpseg",
        ):
            if fake_blob:
                args.append(f"blob={fake_blob}")

        if mode in ("fake", "syndata"):
            add_tls_mod(profile, args)

        lua = "--lua-desync=" + mode
        if args:
            lua += ":" + ":".join(args)

        out.append(lua)

    return out, payload


def build_http_mod_instances(profile: Profile) -> list[str]:
    mods = profile.old_http_mods
    out = []

    if "--hostcase" in mods or "--hostspell" in mods:
        spell = mods.get("--hostspell") or "Host"
        out.append(f"--lua-desync=http_hostcase:spell={spell}")

    if "--domcase" in mods:
        out.append("--lua-desync=http_domcase")

    if "--methodeol" in mods:
        out.append("--lua-desync=http_methodeol")

    if "--unixeol" in mods:
        out.append("--lua-desync=http_unixeol")

    return out


def warn_duplicate_dpi(profile: Profile, idx: int, warnings: list[str]):
    for key, vals in profile.dpi.items():
        if len(vals) > 1:
            joined = ",".join(vals)
            warnings.append(f"profile-{idx}:duplicate-dpi-option:{key}={joined}")


def warn_unhandled_dpi(profile: Profile, idx: int, warnings: list[str]):
    for key, vals in profile.dpi.items():
        if key not in SUPPORTED_DPI_OPTIONS:
            for val in vals:
                warnings.append(f"profile-{idx}:unhandled-dpi:{key}={val}")


def convert_profiles(
    profiles: list[Profile],
    prefer_defaults: bool,
    autofilter_l7: bool,
) -> tuple[list[str], list[str], list[str]]:
    blobs = BlobStore()
    result_profiles = []
    warnings = []
    report = []
    effective_index = 0

    for original_idx, raw_profile in enumerate(profiles, start=1):
        p = classify_profile(raw_profile)
        warn_duplicate_dpi(p, original_idx, warnings)
        warn_unhandled_dpi(p, original_idx, warnings)

        split_profiles_for_l7 = split_l7_specific_profiles(p, warnings)

        for sub_i, sub_profile in enumerate(split_profiles_for_l7):
            effective_index += 1
            prof_out = []

            if effective_index > 1:
                prof_out.append(sub_profile.prefix_new or "--new")
            elif sub_profile.prefix_new:
                prof_out.append(sub_profile.prefix_new)

            filters = list(sub_profile.globals_or_filters)

            lua_instances, inferred_payload = build_lua_instances(
                sub_profile,
                blobs,
                prefer_defaults=prefer_defaults,
                warnings=warnings,
            )

            http_mod_instances = build_http_mod_instances(sub_profile)

            if inferred_payload:
                l7 = L7_BY_PAYLOAD.get(inferred_payload)
                # Do not auto-add discord/stun as payload-derived l7 if it is already split/explicit.
                append_filter_l7_if_missing(filters, l7, autofilter_l7)

            prof_out.extend(filters)

            # Old HTTP modifiers should apply to HTTP requests.
            if http_mod_instances and not has_option(prof_out, "--payload"):
                prof_out.append("--payload=http_req")

            prof_out.extend(http_mod_instances)

            # Payload goes before Lua instances so it applies to them.
            if lua_instances and inferred_payload and not has_option(prof_out, "--payload"):
                prof_out.append(f"--payload={inferred_payload}")

            prof_out.extend(lua_instances)

            if not lua_instances and not http_mod_instances and sub_profile.dpi:
                warnings.append(f"profile-{original_idx}:dpi-options-present-but-no-desync-mode")

            for x in sub_profile.unknown:
                warnings.append(f"profile-{original_idx}:unknown:{x}")

            for x in sub_profile.dropped:
                report.append(f"profile-{original_idx}:dropped:{x}")

            result_profiles.extend(prof_out)

    final = blobs.blobs + result_profiles
    return final, warnings, report


# ----------------------------
# Output
# ----------------------------

def wrap_command(tokens: list[str], bin_name: str, config_style: bool = False) -> str:
    if config_style:
        lines = []
        for t in tokens:
            if (t == "--new" or t.startswith("--new=")) and lines and lines[-1] != "":
                lines.append("")
            lines.append(t)
        return "\n".join(lines)

    lines = [shlex.quote(bin_name) + ' \\']
    for i, t in enumerate(tokens):
        end = ' \\' if i < len(tokens) - 1 else ""
        lines.append("  " + shlex.quote(t) + end)

    return "\n".join(lines)

def write_report(path: Path, warnings: list[str], report: list[str]):
    lines = []
    lines.append("# Conversion report")
    lines.append("")
    lines.append("## Warnings")

    if warnings:
        lines.extend(f"- {x}" for x in warnings)
    else:
        lines.append("- none")

    lines.append("")
    lines.append("## Dropped")

    if report:
        lines.extend(f"- {x}" for x in report)
    else:
        lines.append("- none")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def convert_text(
    src: str,
    *,
    from_opts: bool = False,
    lists_dir: str = "/opt/zapret2/ipset",
    bin_dir: str = "/opt/zapret2/binaries",
    root_dir: str = ".",
    prefer_defaults: bool = False,
    autofilter_l7: bool = True,
) -> tuple[list[str], list[str], list[str]]:
    all_tokens = []

    if from_opts:
        vars_ = {}
        cmd = expand_vars(unescape_batch_carets(src.strip()), vars_, lists_dir, bin_dir)
        all_tokens.extend(tokenize_command(cmd))
    else:
        vars_ = parse_bat_vars(src, root_dir)
        commands = extract_winws_commands(src)

        for cmd in commands:
            cmd = expand_vars(cmd, vars_, lists_dir, bin_dir)
            all_tokens.extend(tokenize_command(cmd))

    profiles = split_profiles(all_tokens)
    return convert_profiles(
        profiles,
        prefer_defaults=prefer_defaults,
        autofilter_l7=autofilter_l7,
    )


# ----------------------------
# Self-tests
# ----------------------------

def self_test_fail(name: str, msg: str):
    raise AssertionError(f"{name}: {msg}")


def assert_contains(name: str, text: str, needle: str):
    if needle not in text:
        self_test_fail(name, f"missing {needle!r}\n{text}")


def assert_not_contains(name: str, text: str, needle: str):
    if needle in text:
        self_test_fail(name, f"unexpected {needle!r}\n{text}")


def run_self_tests():
    tests = []

    # A. Windows-only opts removed, quotes in key=value removed.
    name = "A"
    inp = 'start "zapret" /min "%BIN%winws.exe" --wf-tcp=80,443 --wf-udp=443 --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls="%BIN%tls.bin"'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries", lists_dir="/opt/zapret2/ipset")
    text = "\n".join(converted)
    assert_not_contains(name, text, "--wf-tcp")
    assert_not_contains(name, text, "--wf-udp")
    assert_contains(name, text, "--filter-udp=443")
    assert_contains(name, text, "--filter-tcp=443")
    assert_contains(name, text, "--lua-desync=fake")
    assert_contains(name, text, "--blob=fake_tls_1:@/opt/zapret2/binaries/tls.bin")
    assert_not_contains(name, text, '@"/opt')
    tests.append(name)

    # B. ^! handling.
    name = "B"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls=^!'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries")
    text = "\n".join(converted + warnings + report)
    assert_contains(name, text, "!")
    assert_not_contains(name, text, "^!")
    assert_not_contains(name, text, "^")
    tests.append(name)

    # C. Unexpanded batch vars must be dropped from valid filter opts.
    name = "C"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-udp=%GameFilterUDP% --filter-tcp=443 --dpi-desync=fake'
    converted, warnings, report = convert_text(inp)
    output_text = "\n".join(converted)
    report_text = "\n".join(report)
    assert_not_contains(name, output_text, "%GameFilterUDP%")
    assert_contains(name, report_text, "profile-1:dropped:--filter-udp=%GameFilterUDP%")
    tests.append(name)

    # C2. Mixed concrete ports plus unexpanded vars should keep concrete ports.
    name = "C2"
    inp = 'start "zapret" /min "%BIN%winws.exe" --wf-udp=443,19294-19344,50000-50100,%GameFilterUDP% --filter-tcp=443 --dpi-desync=fake'
    converted, warnings, report = convert_text(inp)
    output_text = "\n".join(converted)
    report_text = "\n".join(report)
    assert_contains(name, output_text, "--filter-udp=443,19294-19344,50000-50100")
    assert_not_contains(name, output_text, "%GameFilterUDP%")
    assert_not_contains(name, report_text, "profile-1:dropped:--wf-udp=443,19294-19344,50000-50100,%GameFilterUDP%")
    tests.append(name)

    # C3. unknown/unknown_udp are blob hints, not valid nfqws2 --payload values.
    name = "C3"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-udp=19294-19344,50000-50100 --dpi-desync=fake --dpi-desync-fake-unknown-udp="%BIN%unknown_udp.bin"'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries")
    text = "\n".join(converted + warnings + report)
    assert_contains(name, text, "--blob=fake_unknown_udp_1:@/opt/zapret2/binaries/unknown_udp.bin")
    assert_contains(name, text, "--lua-desync=fake:blob=fake_unknown_udp_1")
    assert_not_contains(name, text, "--payload=unknown_udp")
    tests.append(name)

    name = "C4"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-tcp=12345 --dpi-desync=fake --dpi-desync-fake-unknown="%BIN%unknown.bin"'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries")
    text = "\n".join(converted + warnings + report)
    assert_contains(name, text, "--blob=fake_unknown_1:@/opt/zapret2/binaries/unknown.bin")
    assert_contains(name, text, "--lua-desync=fake:blob=fake_unknown_1")
    assert_not_contains(name, text, "--payload=unknown")
    tests.append(name)

    # D. Discord/STUN fake blobs.
    name = "D"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%discord.bin" --dpi-desync-fake-stun="%BIN%stun.bin" --dpi-desync-repeats=6'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries")
    text = "\n".join(converted + warnings + report)
    assert_contains(name, text, "--blob=fake_discord_1:@/opt/zapret2/binaries/discord.bin")
    assert_contains(name, text, "--blob=fake_stun_2:@/opt/zapret2/binaries/stun.bin")
    assert_contains(name, text, "--filter-l7=discord")
    assert_contains(name, text, "--filter-l7=stun")
    assert_contains(name, text, "repeats=6")
    tests.append(name)

    # E. Duplicate fake TLS should not be overwritten silently.
    name = "E"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls="%BIN%a.bin" --dpi-desync-fake-tls="%BIN%b.bin"'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries")
    text = "\n".join(converted + warnings + report)
    assert_contains(name, text, "duplicate-dpi-option:--dpi-desync-fake-tls=")
    tests.append(name)

    # F. Reused fake file must create only one --blob.
    name = "F"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-tcp=443 --dpi-desync=fake,multidisorder --dpi-desync-fake-tls="%BIN%same.bin" --new --filter-tcp=443 --dpi-desync=fake --dpi-desync-fake-tls="%BIN%same.bin"'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries")
    text = "\n".join(converted)
    if text.count("@/opt/zapret2/binaries/same.bin") != 1:
        self_test_fail(name, f"duplicate blob for same file\n{text}")
    assert_contains(name, text, "blob=fake_tls_1")
    tests.append(name)

    # G. Config-style output separates every --new strategy by an empty line.
    name = "G"
    formatted = wrap_command(["--filter-tcp=443", "--lua-desync=fake", "--new", "--filter-udp=443"], "nfqws2", config_style=True)
    assert_contains(name, formatted, "--lua-desync=fake\n\n--new\n--filter-udp=443")
    tests.append(name)

    # H. Hostlist options must be stripped from output and reported as dropped.
    name = "H"
    inp = 'start "zapret" /min "%BIN%winws.exe" --filter-tcp=443 --hostlist="%LISTS%list-general.txt" --hostlist-exclude-domains=example.org --hostlist-auto=/tmp/auto.txt --dpi-desync=fake --dpi-desync-fake-tls="%BIN%tls.bin"'
    converted, warnings, report = convert_text(inp, bin_dir="/opt/zapret2/binaries", lists_dir="/opt/zapret2/ipset")
    output_text = "\n".join(converted)
    report_text = "\n".join(report)
    assert_not_contains(name, output_text, "--hostlist")
    assert_not_contains(name, output_text, "list-general.txt")
    assert_contains(name, report_text, "profile-1:dropped:--hostlist=/opt/zapret2/ipset/list-general.txt")
    assert_contains(name, report_text, "profile-1:dropped:--hostlist-exclude-domains=example.org")
    assert_contains(name, report_text, "profile-1:dropped:--hostlist-auto=/tmp/auto.txt")
    tests.append(name)

    print("SELF-TEST OK")
    print("passed: " + ", ".join(tests))


# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Smart converter: Flowseal/winws zapret1 options -> zapret2 nfqws2 Lua options"
    )

    ap.add_argument("input", nargs="?", help="general.bat или файл со строкой winws/nfqws опций")
    ap.add_argument("-o", "--output", default="-", help="Куда писать результат. '-' = stdout")

    ap.add_argument("--from-opts", action="store_true",
                    help="Вход — уже строка опций, не .bat")

    ap.add_argument("--nfqws2-bin", default="nfqws2")
    ap.add_argument("--lists-dir", default="/opt/zapret2/ipset")
    ap.add_argument("--bin-dir", default="/opt/zapret2/binaries")
    ap.add_argument("--root-dir", default=".", help="Замена для %%~dp0")

    ap.add_argument("--wrap", action="store_true",
                    help="Вывести многострочную shell-команду")

    ap.add_argument("--config-style", action="store_true",
                    help="Вывести опции по одной на строку, без nfqws2 и без backslash")

    ap.add_argument("--prefer-default-blobs", action="store_true",
                    help="Использовать fake_default_tls/http/quic вместо файлов Flowseal")

    ap.add_argument("--no-autofilter-l7", action="store_true",
                    help="Не добавлять --filter-l7 автоматически")

    ap.add_argument("--report", default=None,
                    help="Файл отчёта о выкинутых/сомнительных опциях")

    ap.add_argument("--dry-run", action="store_true",
                    help="Добавить --dry-run в результат")

    ap.add_argument("--self-test", action="store_true",
                    help="Запустить встроенные самотесты и выйти")

    args = ap.parse_args()

    if args.self_test:
        run_self_tests()
        return

    if not args.input:
        ap.error("input is required unless --self-test is used")

    src_path = Path(args.input)
    src = src_path.read_text(encoding="utf-8", errors="ignore")

    converted, warnings, report = convert_text(
        src,
        from_opts=args.from_opts,
        lists_dir=args.lists_dir,
        bin_dir=args.bin_dir,
        root_dir=args.root_dir,
        prefer_defaults=args.prefer_default_blobs,
        autofilter_l7=not args.no_autofilter_l7,
    )

    if args.dry_run and not any(x.startswith("--dry-run") for x in converted):
        converted.insert(0, "--dry-run")

    if args.config_style:
        text = wrap_command(converted, args.nfqws2_bin, config_style=True) + "\n"
    elif args.wrap:
        text = wrap_command(converted, args.nfqws2_bin) + "\n"
    else:
        text = shell_join(converted) + "\n"

    if warnings:
        text += "\n# WARNINGS:\n"
        text += "\n".join(f"# {x}" for x in warnings) + "\n"

    if args.output == "-":
        print(text, end="")
    else:
        Path(args.output).write_text(text, encoding="utf-8")

    if args.report:
        write_report(Path(args.report), warnings, report)


if __name__ == "__main__":
    main()

"""Deterministic IOC extraction. Never trust a model to copy hashes or IPs accurately."""
from __future__ import annotations

import re

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>)\]]+", re.I)
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Strings that look like domains but are file names.
_FILE_EXT = {
    "dll", "exe", "sys", "txt", "log", "dat", "tmp", "bat", "cmd", "ps1", "vbs", "js", "py", "sh",
    "doc", "docx", "xls", "xlsx", "pdf", "zip", "rar", "jpg", "png", "gif", "ini", "cfg", "conf",
    "json", "xml", "yml", "yaml", "lnk", "scr", "msi", "bin", "so", "ko", "cpp", "java", "html",
}
_CAP = 200


def refang(text: str) -> str:
    text = re.sub(r"(?i)hxxp", "http", text)
    for a, b in (("[.]", "."), ("(.)", "."), ("[:]", ":"), ("[at]", "@"), ("[@]", "@")):
        text = text.replace(a, b)
    return text


def defang(value: str) -> str:
    return re.sub(r"(?i)^http", "hxxp", value).replace(".", "[.]")


def extract(text: str) -> dict[str, list[str]]:
    text = refang(text)
    urls = sorted(set(_URL.findall(text)))
    ips = sorted(set(_IPV4.findall(text)))
    emails = sorted(set(_EMAIL.findall(text)))
    hashes = {
        "sha256": sorted({h.lower() for h in _SHA256.findall(text)}),
        "sha1": sorted({h.lower() for h in _SHA1.findall(text)}),
        "md5": sorted({h.lower() for h in _MD5.findall(text)}),
    }
    email_domains = {e.split("@", 1)[1].lower() for e in emails}
    domains = set()
    for d in _DOMAIN.findall(text):
        d = d.lower()
        if d.rsplit(".", 1)[1] in _FILE_EXT or _IPV4.fullmatch(d) or d in email_domains:
            continue
        domains.add(d)
    return {
        "ipv4": ips[:_CAP],
        "domains": sorted(domains)[:_CAP],
        "urls": urls[:_CAP],
        "emails": emails[:_CAP],
        **{k: v[:_CAP] for k, v in hashes.items()},
    }

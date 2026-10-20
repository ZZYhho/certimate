#!/usr/bin/env python3
"""Rebuild the offline Android CA dataset from pinned, immutable AOSP commits.

Requires Python 3.10+ and network access only when updating. --verify is offline.
No machine trust store or previously downloaded certificates are used as fallback.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import io
import json
from pathlib import Path
import re
import ssl
import tarfile
import time
import urllib.error
import urllib.request


DATA = Path(__file__).resolve().parents[1] / "internal/certcompat/data"
DATA_VERSION = "2026-10-20"
AOSP = "https://android.googlesource.com/platform/"
# First release tags except the documented patch-release baselines for 4.x/5.1.
# Never silently replace an unavailable historical profile with a newer CA set.
RELEASES = [
    ("4.1", "4.1.1", "03255f860520d940b42bba989145f8485d6e332e"),
    ("4.2", "4.2.2", "cc55503ccef76a3b443b1dba3a2f05049b2b34f4"),
    ("4.3", "4.3", "339f18ff18ea0c13fae1d6750ffe8eaf847e62e9"),
    ("4.4", "4.4.4", "9b24ebf95f897a75c60c9c68d00694406afa6fbc"),
    ("5.0", "5.0.0", "45e02606b35996f61487f512ee91d0df83e75c9e"),
    ("5.1", "5.1.1", "1872f348c4fe99929898ccde33ff84d26711ba76"),
    ("6.0", "6.0.0", "b670c900b31d85720ce8d82c4d01003ec09784f6"),
    ("7.0", "7.0.0", "c36d8eb8071d73528993e024e73d40c6977b1d0d"),
    ("7.1", "7.1.0", "465b0d86e7c407ed22e8f674906d3fa5e6e53de5"),
    ("7.1.1", "7.1.1", "51300a813051dcaaf3dc07000e92ed40a27a2b21"),
    ("8.0", "8.0.0", "db524b256a637f18588c1d5ecc4a7d43cdebf8fd"),
    ("8.1", "8.1.0", "93fc85e19c5e5ac4c11f893d87a3bc5bbbac4c6d"),
    ("9", "9.0.0", "698a25049345a31eb7d55d08ad9a2a6bbe3a5371"),
    ("10", "10.0.0", "ea03514ced2302d45c35b9ea6553813346affa12"),
    ("11", "11.0.0", "81467359abd72f5990dad119520355194c779c8f"),
    ("12", "12.0.0", "0c3ddfb33b5fde7ff6d20cfdef61306ac942abb0"),
    ("12.1", "12.1.0", "67a8a8e470a0169ffdc613eced511e102575f207"),
    ("13", "13.0.0", "45dbcd031d38cd72431580445a9bea773f9e0f95"),
    ("14", "14.0.0", "9c84d3849b18d670683ff834a4e7870be26487c7"),
    ("15", "15.0.0", "2207c6dd74f18819bbaa4566d1e6c5d956a452fd"),
    ("16", "16.0.0", "621d52a801b5584ad26abee653ec2e2d09de9ce9"),
    ("17", "17.0.0", "0499c160c1c1d6ffa6b3fe3019de692bc8875458"),
]
# Preserve the upstream notices alongside the extracted certificates. CA
# certificates have their issuers' terms, not automatically this repo's license.
SOURCE_NOTICES = {
    "system-ca-certificates.METADATA": f"{AOSP}system/ca-certificates/+/0499c160c1c1d6ffa6b3fe3019de692bc8875458/METADATA?format=TEXT",
    "system-ca-certificates.README.cacerts": f"{AOSP}system/ca-certificates/+/0499c160c1c1d6ffa6b3fe3019de692bc8875458/README.cacerts?format=TEXT",
    "libcore.NOTICE": f"{AOSP}libcore/+/03255f860520d940b42bba989145f8485d6e332e/NOTICE?format=TEXT",
}
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----")


def fetch(url: str) -> bytes:
    for attempt in range(5):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Certimate-Android-Truststore-Updater/1"})
            with urllib.request.urlopen(request, timeout=45) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 4:
                raise
            time.sleep(min(2 ** attempt, 8))
    raise AssertionError("unreachable")


def git_json(url: str) -> dict:
    body = fetch(url)
    if not body.startswith(b")]}'\n"):
        raise ValueError(f"Invalid Gitiles JSON: {url}")
    return json.loads(body[5:])


def profile_source(release: tuple[str, str, str]) -> tuple[dict, list[dict]]:
    version, release_tag, revision = release
    old = int(version.split(".")[0]) <= 6
    repository = AOSP + ("libcore" if old else "system/ca-certificates")
    path = "luni/src/main/files/cacerts" if old else "files"
    tag = f"android-{release_tag}_r1"
    actual_revision = git_json(f"{repository}/+/{tag}?format=JSON")["commit"]
    if actual_revision != revision:
        raise ValueError(f"Tag {tag} moved: expected {revision}, got {actual_revision}")
    tree = git_json(f"{repository}/+/{revision}/{path}/?format=JSON")
    entries = tree["entries"]
    if not entries or any(e["type"] != "blob" or not re.fullmatch(r"[a-f0-9]{8}\.\d+", e["name"]) for e in entries):
        raise ValueError(f"Unexpected CA directory contents for Android {version}")
    return {"version": version, "repository": repository, "revision": revision, "tag": tag, "path": path}, entries


def extract_certificate(raw: bytes) -> tuple[str, bytes]:
    matches = list(PEM.finditer(raw))
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one PEM certificate, found {len(matches)}")
    der = base64.b64decode(re.sub(rb"\s", b"", matches[0][1]), validate=True)
    # SSLContext uses OpenSSL to ensure the DER actually encodes an X.509 certificate.
    pem = ssl.DER_cert_to_PEM_cert(der).encode("ascii")
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem.decode("ascii"))
    return hashlib.sha256(der).hexdigest(), pem


def download_profile(source: tuple[dict, list[dict]]) -> list[tuple[str, str, bytes]]:
    profile, entries = source
    url = f"{profile['repository']}/+archive/{profile['revision']}/{profile['path']}.tar.gz"
    archive = fetch(url)
    # A directory archive avoids hundreds of individual Gitiles requests. Verify
    # every original file against the separately fetched immutable Git tree.
    expected = {entry["name"]: entry["id"] for entry in entries}
    certificates = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = bundle.getmembers()
        if {member.name for member in members} != set(expected) or any(not member.isfile() for member in members):
            raise ValueError(f"Archive contents do not match Git tree for Android {profile['version']}")
        for member in members:
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError(f"Missing archive member: {member.name}")
            raw = stream.read()
            blob = expected[member.name]
            actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            if actual != blob:
                raise ValueError(f"Git blob hash mismatch: Android {profile['version']} {member.name}")
            fingerprint, pem = extract_certificate(raw)
            certificates.append((blob, fingerprint, pem))
    return certificates


def verify(data_dir: Path) -> dict:
    manifest = json.loads((data_dir / "profiles.json").read_text())
    for filename in SOURCE_NOTICES:
        if not (data_dir / "source-notices" / filename).is_file():
            raise ValueError(f"Missing upstream notice: {filename}")
    if len(manifest["profiles"]) != len(RELEASES):
        raise ValueError("Unexpected profile count")
    referenced = set()
    for profile, (version, release, revision) in zip(manifest["profiles"], RELEASES):
        if (profile["version"], profile["tag"], profile["revision"]) != (version, f"android-{release}_r1", revision):
            raise ValueError(f"Incorrect provenance for {version}")
        roots = profile["roots"]
        if not roots or roots != sorted(set(roots)):
            raise ValueError(f"Empty, unsorted or duplicate roots for {version}")
        referenced.update(roots)
    available = {p.stem for p in (data_dir / "roots").glob("*.pem")}
    if available != referenced:
        raise ValueError("Root files and profile references differ")
    for fingerprint in sorted(referenced):
        raw = (data_dir / "roots" / f"{fingerprint}.pem").read_bytes()
        actual, canonical = extract_certificate(raw)
        if actual != fingerprint or raw != canonical:
            raise ValueError(f"Root hash or canonical PEM mismatch: {fingerprint}")
    print(f"Verified {len(manifest['profiles'])} Android profiles, {len(referenced)} unique roots")
    for profile in manifest["profiles"]:
        print(f"Android {profile['version']}: {len(profile['roots'])} roots")
    return manifest


def update(data_dir: Path, workers: int) -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        sources = list(pool.map(profile_source, RELEASES))
        print(f"Downloading {len(sources)} immutable Android CA directory archives", flush=True)
        certificates = [cert for profile_certs in pool.map(download_profile, sources) for cert in profile_certs]
        notices = dict(zip(SOURCE_NOTICES, pool.map(lambda url: base64.b64decode(fetch(url), validate=True), SOURCE_NOTICES.values())))
    # Do not touch the existing dataset until all remote data validates.
    roots = {fingerprint: pem for _, fingerprint, pem in certificates}
    fingerprints = {blob: fingerprint for blob, fingerprint, _ in certificates}
    profiles = []
    for profile, entries in sources:
        profiles.append({**profile, "roots": sorted({fingerprints[e["id"]] for e in entries})})
    root_dir = data_dir / "roots"
    root_dir.mkdir(parents=True, exist_ok=True)
    notice_dir = data_dir / "source-notices"
    notice_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in notices.items():
        (notice_dir / filename).write_bytes(content)
    for fingerprint, pem in sorted(roots.items()):
        (root_dir / f"{fingerprint}.pem").write_bytes(pem)
    manifest = {"version": DATA_VERSION, "profiles": profiles}
    (data_dir / "profiles.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    for path in root_dir.glob("*.pem"):
        if path.stem not in roots:
            path.unlink()
    verify(data_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true", help="Verify checked-in dataset offline, without changing files")
    parser.add_argument("--data-dir", type=Path, default=DATA)
    parser.add_argument("--workers", type=int, default=6, choices=range(1, 17), metavar="1..16")
    args = parser.parse_args()
    if args.verify:
        verify(args.data_dir)
    else:
        update(args.data_dir, args.workers)


if __name__ == "__main__":
    main()

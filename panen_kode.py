import hashlib
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

TARGETS = [
    "https://raw.githubusercontent.com/projectdiscovery/httpx/main/runner/runner.go",
    "https://raw.githubusercontent.com/projectdiscovery/subfinder/dev/v2/pkg/runner/runner.go",
    "https://raw.githubusercontent.com/projectdiscovery/nuclei/main/internal/runner/runner.go",
    "https://raw.githubusercontent.com/projectdiscovery/katana/main/internal/runner/runner.go",
    "https://raw.githubusercontent.com/epi052/feroxbuster/main/src/scanner/ferox_scanner.rs",
    "https://raw.githubusercontent.com/bishopfox/phishuntangler/main/phishuntangler.py",
    "https://raw.githubusercontent.com/rednaga/APKiD/master/apkid/apkid.py",
    "https://raw.githubusercontent.com/d-Rickyy-b/certstream-server-go/master/internal/certstream/watcher.go",
]

OUT_DIR = Path("loot_kode")
MANIFEST_PATH = OUT_DIR / "manifest.jsonl"


def fetch_target(url: str) -> dict:
    parts = urlparse(url).path.strip("/").split("/")
    owner, repo, branch = parts[0], parts[1], parts[2]
    rel_path = Path(*parts[3:])
    dest = OUT_DIR / owner / repo / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TuyulHarvester/1.0 (Python-3.15t)"},
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_bytes = resp.read()
            dest.write_bytes(raw_bytes)
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "ok",
                "repo": f"{owner}/{repo}",
                "branch": branch,
                "local_path": str(dest),
                "bytes": len(raw_bytes),
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "url": url,
            }
    except urllib.error.URLError as exc:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "error",
            "repo": f"{owner}/{repo}",
            "error": str(exc),
            "url": url,
        }


def main() -> None:
    gil_status = getattr(sys, "_is_gil_enabled", lambda: True)()
    print(f"[*] Python {sys.version.split()[0]} | GIL aktif: {gil_status}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    with ThreadPoolExecutor(max_workers=len(TARGETS)) as pool:
        futures = {pool.submit(fetch_target, url): url for url in TARGETS}
        for future in as_completed(futures):
            record = future.result()
            results.append(record)
            if record["status"] == "ok":
                print(f"[+] {record['repo']} -> {record['local_path']} ({record['bytes']} B)")
            else:
                print(f"[-] GAGAL {record['repo']}: {record['error']}")

    with MANIFEST_PATH.open("a", encoding="utf-8") as mf:
        for item in results:
            mf.write(json.dumps(item) + "\n")

    print(f"\n[✓] Selesai. Manifest tercatat di {MANIFEST_PATH}")


if __name__ == "__main__":
    main()
  

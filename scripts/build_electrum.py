#!/usr/bin/env python3
"""Build a self-contained Electrum plugin ZIP using only the standard library."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import platform
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "src/passphrase_leak_checker/electrum"
PLUGIN_ID = "electrum_passphrase_leak_checker"


def build(output_dir: Path) -> Path:
    manifest = json.loads((PLUGIN / "manifest.json").read_text())
    module = ast.parse((ROOT / "src/passphrase_leak_checker/__init__.py").read_text())
    version = next(ast.literal_eval(node.value) for node in module.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "__version__"
                           for target in node.targets))
    if manifest["version"] != version:
        raise ValueError("Core and Electrum manifest versions must match before building.")
    if manifest["name"] != PLUGIN_ID:
        raise ValueError("Electrum plugin ID must match its installed package name.")
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"electrum-passphrase-leak-checker-{version}.zip"
    sources = {name: PLUGIN / name for name in (
        "__init__.py", "qt.py", "inline_controls.py", "network_policy.py", "http_transport.py", "secret_policy.py", "manifest.json",
    )}
    sources["pwned_api.py"] = ROOT / "src/passphrase_leak_checker/client.py"
    sources["LICENSE"] = ROOT / "LICENSE"
    contents = {name: path.read_bytes() for name, path in sources.items()}
    # Stable ordering, timestamps, and permissions make repeated builds identical.
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, path in sorted(sources.items()):
            info = zipfile.ZipInfo(f"{PLUGIN_ID}/{name}", date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, contents[name])
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.zip.sha256').write_text(f'{digest}  {output.name}\n', encoding='ascii')
    provenance = {
        'schema': 1,
        'artifact': {'name': output.name, 'sha256': digest},
        'builder': {'path': 'scripts/build_electrum.py',
                    'sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'runtime': {'python': platform.python_version(), 'zlib': zlib.ZLIB_VERSION},
        'inputs': {name: {'path': path.relative_to(ROOT).as_posix(),
                         'sha256': hashlib.sha256(contents[name]).hexdigest()}
                   for name, path in sorted(sources.items())},
    }
    output.with_suffix('.provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True) + '\n',
                                                     encoding='utf-8')
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    print(build(args.output_dir))


if __name__ == "__main__":
    main()

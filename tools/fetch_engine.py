"""Fetch only the fixed official engine asset and verify both hashes; not build a kernel."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

URL = 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-linux-amd64-v1-v1.19.30.gz'
COMPRESSED_SHA256 = 'cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553'
BINARY_SHA256 = '20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494'


def fetch(output, cached_archive=None):
    output = Path(output).absolute()
    if output.exists():
        if hashlib.sha256(output.read_bytes()).hexdigest() == BINARY_SHA256:
            return {'status': 'EXISTING_VERIFIED', 'sha256': BINARY_SHA256}
        raise ValueError('REFUSE_OVERWRITE_DIFFERENT_ENGINE')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.engine-', dir=output.parent) as tmp:
        directory = Path(tmp); archive = directory / 'engine.gz'
        if cached_archive:
            import shutil
            shutil.copyfile(cached_archive, archive)
        else:
            subprocess.run(['curl', '-fsSL', '--proto', '=https', '--proto-redir', '=https',
                            '--connect-timeout', '10', '--max-time', '180', '--max-filesize', '30000000',
                            URL, '-o', str(archive)], check=True, timeout=185)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != COMPRESSED_SHA256:
            raise ValueError('OFFICIAL_ASSET_HASH_MISMATCH')
        with gzip.open(archive, 'rb') as stream:
            binary = stream.read(70000001)
        if len(binary) > 70000000 or hashlib.sha256(binary).hexdigest() != BINARY_SHA256:
            raise ValueError('ENGINE_BINARY_HASH_MISMATCH')
        file = directory / 'mihomo'; file.write_bytes(binary); file.chmod(0o755)
        # Exact absent destination only; never replace an existing host engine.
        os.link(file, output)
    return {'status': 'DOWNLOADED_VERIFIED', 'sha256': BINARY_SHA256}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True)
    parser.add_argument('--archive', help='Optional already-downloaded gzip; both hashes still verified')
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.output, args.archive)))
    except Exception as exc:
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(json.dumps({'status': 'FAILED', 'code': message})); raise SystemExit(1)

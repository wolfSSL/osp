#!/usr/bin/env python3
"""Extract actual applied OpenZFS functions without changing their bodies."""

import hashlib
import json
from pathlib import Path
import re
import sys


# Ignore braces inside C strings, character literals, and comments.
C_TOKENS = re.compile(
    r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',
    re.DOTALL,
)


def extract(source_root, relative_path, names, manifest):
    source = (source_root / relative_path).read_text()
    manifest[relative_path] = hashlib.sha256(source.encode()).hexdigest()
    chunks = []
    for name in names:
        declaration = re.search(
            r"(?m)^(?:static )?(?:int|void)\n" + re.escape(name) + r"\(",
            source,
        )
        if declaration is None:
            raise ValueError(f"Cannot locate function {name} in {relative_path}")
        depth = 0
        for token in C_TOKENS.finditer(source, declaration.end()):
            if token.group() == "{":
                depth += 1
            elif token.group() == "}":
                depth -= 1
                if depth == 0:
                    chunks.append(source[declaration.start():token.end()] + "\n")
                    break
        else:
            raise ValueError(f"Unterminated function {name} in {relative_path}")
    notices = source[:source.index("#include")]
    return (
        notices
        + "\n/* Exact function extraction for regression harness. */\n"
        + "\n".join(chunks)
    )


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: extract.py APPLIED_SOURCE_TREE OUTPUT_DIRECTORY")
    source_root = Path(sys.argv[1]).resolve(strict=True)
    output_dir = Path(sys.argv[2]).resolve(strict=True)
    manifest = {}
    selections = {
        "actual-gcm.c": (
            "module/icp/algs/modes/gcm.c",
            [
                "gcm_reserve_data",
                "gcm_save_data",
                "gcm_mode_encrypt_contiguous_blocks",
                "gcm_encrypt_final",
                "gcm_mode_decrypt_contiguous_blocks",
                "gcm_decrypt_final",
                "gcm_validate_args",
                "gcm_init_ctx",
            ],
        ),
        "actual-clear.c": (
            "module/icp/algs/modes/modes.c", ["gcm_clear_ctx"],
        ),
        "actual-update.c": (
            "module/icp/core/kcf_prov_lib.c",
            ["crypto_update_iov", "crypto_update_uio"],
        ),
        "actual-atomic.c": (
            "module/icp/io/aes.c", ["aes_encrypt_atomic", "aes_decrypt_atomic"],
        ),
    }
    for filename, (relative_path, names) in selections.items():
        extracted = extract(source_root, relative_path, names, manifest)
        (output_dir / filename).write_text(extracted)
    provenance = {
        "source_tree": str(source_root),
        "files_sha256": manifest,
        "limit": (
            "Exact functions compiled; kernel types, key init, CCM and wolfCrypt "
            "API are harness seams. No validated-module runtime claim."
        ),
    }
    (output_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n"
    )


if __name__ == "__main__":
    main()

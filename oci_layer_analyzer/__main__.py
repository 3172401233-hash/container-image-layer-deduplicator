"""CLI entry point: python -m oci_layer_analyzer <manifest.json>

Reads the manifest and local layer tarballs, prints a JSON planning report.
Never modifies any image data.
"""
import json
import sys

from .analyzer import analyze_manifest


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write("usage: python -m oci_layer_analyzer <manifest.json>\n")
        return 2
    with open(argv[0], "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    report = analyze_manifest(manifest)
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

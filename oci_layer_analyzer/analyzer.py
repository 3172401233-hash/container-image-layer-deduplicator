"""Cross-image content indexing and reuse planning.

Planning principles:
- Layer-level reuse is keyed on the diffID (uncompressed layer digest); the
  local tar's actual digest is verified and mismatched layers are excluded.
- File-level reuse is keyed on the content sha256, never on the file name;
  same-name/different-content paths are reported as conflicts.
- Hard links only share the underlying content blob; files with different
  hard-link semantics are never force-merged into one link group.
- Unsafe entries (path traversal etc.) are recorded as risks only and never
  take part in dedup.
- Purely static planning: no original image data is ever modified.
"""
from __future__ import annotations

from typing import Dict, Tuple

from .models import FILE, HARDLINK, ImageManifest, LayerIndex
from .tarindex import index_layer


class Analyzer:
    def __init__(self, verify_diff_id: bool = True):
        self.verify_diff_id = verify_diff_id

    def analyze(self, manifest: Dict) -> Dict:
        images = [ImageManifest.from_dict(d) for d in manifest.get("images", [])]
        # Global content store: digest -> first-seen (image, path). The first
        # occurrence is the authoritative copy in the shared content store.
        content_store: Dict[str, Tuple[str, str]] = {}
        # diffID -> name of the image where the layer was first seen.
        layer_store: Dict[str, str] = {}
        # path -> {digest: set(image names)} for conflict detection.
        path_map: Dict[str, Dict[str, set]] = {}

        reports: Dict[str, Dict] = {}
        for image in images:
            reports[image.name] = self._empty_report()
            for descriptor in image.layers:
                layer = index_layer(descriptor)
                report = reports[image.name]
                if not self._layer_usable(layer, report):
                    continue
                if layer.descriptor.diff_id in layer_store:
                    report["reusable_layers"].append(
                        {
                            "diff_id": layer.descriptor.diff_id,
                            "reused_from": layer_store[layer.descriptor.diff_id],
                            "saved_bytes": layer.tar_size,
                        }
                    )
                    report["estimated_savings_bytes"] += layer.tar_size
                    continue
                layer_store[layer.descriptor.diff_id] = image.name
                self._plan_file_reuse(image, layer, report, content_store)
                self._collect_whiteouts_and_links(layer, report)
                for entry in layer.regular_files():
                    by_digest = path_map.setdefault(entry.path, {})
                    by_digest.setdefault(entry.digest, set()).add(image.name)

        for image in images:
            self._collect_conflicts(image, reports[image.name], path_map)

        return {"images": reports, "summary": self._summarize(reports)}

    @staticmethod
    def _empty_report() -> Dict:
        return {
            "reusable_layers": [],
            "reusable_files": [],
            "estimated_savings_bytes": 0,
            "conflicts": [],
            "unsafe_items": [],
            "unusable_layers": [],
            "whiteouts": [],
            "hardlink_notes": [],
        }

    def _layer_usable(self, layer: LayerIndex, report: Dict) -> bool:
        if not layer.ok:
            report["unusable_layers"].append(
                {"diff_id": layer.descriptor.diff_id, "reason": layer.error}
            )
            return False
        if self.verify_diff_id and layer.computed_diff_id != layer.descriptor.diff_id:
            report["unusable_layers"].append(
                {
                    "diff_id": layer.descriptor.diff_id,
                    "reason": "diff_id mismatch: computed %s" % layer.computed_diff_id,
                }
            )
            return False
        for item in layer.unsafe:
            report["unsafe_items"].append(
                {
                    "diff_id": layer.descriptor.diff_id,
                    "path": item.path,
                    "reason": item.reason,
                }
            )
        return True

    def _plan_file_reuse(
        self,
        image: ImageManifest,
        layer: LayerIndex,
        report: Dict,
        content_store: Dict[str, Tuple[str, str]],
    ) -> None:
        digests_in_layer = {e.path: e.digest for e in layer.regular_files()}
        for entry in layer.entries:
            if entry.kind == HARDLINK:
                # A hard link adds no new content; record its semantics and
                # never merge it into a different link group.
                if entry.link_target not in digests_in_layer:
                    report["unsafe_items"].append(
                        {
                            "diff_id": layer.descriptor.diff_id,
                            "path": entry.path,
                            "reason": "hardlink target missing in layer: %s"
                            % entry.link_target,
                        }
                    )
                else:
                    report["hardlink_notes"].append(
                        {
                            "path": entry.path,
                            "target": entry.link_target,
                            "content_digest": digests_in_layer[entry.link_target],
                            "note": "hardlink semantics preserved; content blob may "
                            "be shared but files are not merged into one link group",
                        }
                    )
                continue
            if entry.kind != FILE or entry.digest is None:
                continue
            if entry.digest in content_store:
                src_image, src_path = content_store[entry.digest]
                report["reusable_files"].append(
                    {
                        "path": entry.path,
                        "digest": entry.digest,
                        "size": entry.size,
                        "reused_from": {"image": src_image, "path": src_path},
                    }
                )
                report["estimated_savings_bytes"] += entry.size
            else:
                content_store[entry.digest] = (image.name, entry.path)

    @staticmethod
    def _collect_whiteouts_and_links(layer: LayerIndex, report: Dict) -> None:
        for entry in layer.entries:
            if entry.kind in ("whiteout", "opaque_whiteout"):
                report["whiteouts"].append(
                    {
                        "diff_id": layer.descriptor.diff_id,
                        "path": entry.path,
                        "kind": entry.kind,
                        "note": "whiteout metadata only; excluded from content dedup",
                    }
                )

    @staticmethod
    def _collect_conflicts(
        image: ImageManifest, report: Dict, path_map: Dict[str, Dict[str, set]]
    ) -> None:
        for path, by_digest in sorted(path_map.items()):
            if len(by_digest) <= 1:
                continue
            mine = [d for d, names in by_digest.items() if image.name in names]
            others = {
                d: sorted(names)
                for d, names in by_digest.items()
                if image.name not in names
            }
            for digest in mine:
                report["conflicts"].append(
                    {
                        "path": path,
                        "digest": digest,
                        "reason": "same path with different content across images; "
                        "cannot be merged by name",
                        "conflicting": [
                            {"digest": d, "images": names} for d, names in others.items()
                        ],
                    }
                )

    @staticmethod
    def _summarize(reports: Dict[str, Dict]) -> Dict:
        return {
            "image_count": len(reports),
            "total_estimated_savings_bytes": sum(
                r["estimated_savings_bytes"] for r in reports.values()
            ),
            "total_reusable_layers": sum(
                len(r["reusable_layers"]) for r in reports.values()
            ),
            "total_reusable_files": sum(
                len(r["reusable_files"]) for r in reports.values()
            ),
            "total_conflicts": sum(len(r["conflicts"]) for r in reports.values()),
            "total_unsafe_items": sum(len(r["unsafe_items"]) for r in reports.values()),
        }


def analyze_manifest(manifest: Dict, verify_diff_id: bool = True) -> Dict:
    """Convenience entry point: manifest dict in, planning report dict out."""
    return Analyzer(verify_diff_id=verify_diff_id).analyze(manifest)

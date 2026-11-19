"""Tests for the OCI image layer analyzer. Run with: python -m unittest"""
import hashlib
import io
import os
import shutil
import tarfile
import tempfile
import unittest

from oci_layer_analyzer import analyze_manifest


def _diff_id(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def make_tar(entries):
    """Build a tar in memory from (name, kind, payload) tuples."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.type = tarfile.REGTYPE
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tf.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tf.addfile(info)
            else:
                raise ValueError(kind)
    return buf.getvalue()


class AnalyzerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oci-analyzer-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._counter = 0

    def write_layer(self, raw):
        self._counter += 1
        path = os.path.join(self.tmp, "layer-%d.tar" % self._counter)
        with open(path, "wb") as fh:
            fh.write(raw)
        return {
            "diff_id": _diff_id(raw),
            "compressed_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "compressed_size": len(raw),
            "tar_path": path,
        }

    def image(self, name, layers):
        return {"name": name, "layers": layers}


class TestIdenticalLayers(AnalyzerTestCase):
    def test_identical_layer_shared_across_images(self):
        raw = make_tar([("app/main.py", "file", b"print('hi')\n")])
        layer = self.write_layer(raw)
        report = analyze_manifest(
            {"images": [self.image("img-a", [layer]), self.image("img-b", [layer])]}
        )
        rep_a = report["images"]["img-a"]
        rep_b = report["images"]["img-b"]
        self.assertEqual(rep_a["reusable_layers"], [])
        self.assertEqual(len(rep_b["reusable_layers"]), 1)
        self.assertEqual(rep_b["reusable_layers"][0]["reused_from"], "img-a")
        self.assertEqual(rep_b["reusable_layers"][0]["saved_bytes"], len(raw))
        self.assertEqual(rep_b["estimated_savings_bytes"], len(raw))
        # A fully reused layer must not also count file-level savings.
        self.assertEqual(rep_b["reusable_files"], [])


class TestFileLevelDuplicates(AnalyzerTestCase):
    def test_shared_file_in_different_layers(self):
        shared = b"shared library bytes" * 10
        layer_a = self.write_layer(
            make_tar([("lib/libc.so", "file", shared), ("a.txt", "file", b"a")])
        )
        layer_b = self.write_layer(
            make_tar([("opt/libc.so", "file", shared), ("b.txt", "file", b"b")])
        )
        report = analyze_manifest(
            {"images": [self.image("img-a", [layer_a]), self.image("img-b", [layer_b])]}
        )
        rep_b = report["images"]["img-b"]
        self.assertEqual(rep_b["reusable_layers"], [])
        self.assertEqual(len(rep_b["reusable_files"]), 1)
        reused = rep_b["reusable_files"][0]
        self.assertEqual(reused["path"], "opt/libc.so")
        self.assertEqual(reused["size"], len(shared))
        self.assertEqual(reused["reused_from"], {"image": "img-a", "path": "lib/libc.so"})
        self.assertEqual(rep_b["estimated_savings_bytes"], len(shared))


class TestWhiteouts(AnalyzerTestCase):
    def test_whiteout_entries_recorded_not_deduplicated(self):
        raw = make_tar(
            [
                ("etc/.wh.old.conf", "file", b""),
                ("var/.wh..wh..opq", "file", b""),
                ("etc/keep.conf", "file", b"keep"),
            ]
        )
        layer = self.write_layer(raw)
        report = analyze_manifest({"images": [self.image("img-a", [layer])]})
        rep = report["images"]["img-a"]
        whiteouts = {w["path"] for w in rep["whiteouts"]}
        self.assertEqual(whiteouts, {"etc/.wh.old.conf", "var/.wh..wh..opq"})
        kinds = {w["path"]: w["kind"] for w in rep["whiteouts"]}
        self.assertEqual(kinds["var/.wh..wh..opq"], "opaque_whiteout")
        # Whiteouts carry no content and must never appear as reusable files.
        self.assertEqual(rep["reusable_files"], [])
        self.assertEqual(rep["unsafe_items"], [])


class TestCorruptTar(AnalyzerTestCase):
    def test_corrupt_tar_reported_unusable(self):
        good = self.write_layer(make_tar([("ok.txt", "file", b"ok")]))
        bad_path = os.path.join(self.tmp, "broken.tar")
        with open(bad_path, "wb") as fh:
            fh.write(b"this is definitely not a tar file" * 8)
        bad = {
            "diff_id": "sha256:" + "0" * 64,
            "compressed_digest": "",
            "compressed_size": 0,
            "tar_path": bad_path,
        }
        report = analyze_manifest(
            {"images": [self.image("img-a", [good]), self.image("img-b", [bad])]}
        )
        rep_b = report["images"]["img-b"]
        self.assertEqual(len(rep_b["unusable_layers"]), 1)
        self.assertIn("corrupt tar", rep_b["unusable_layers"][0]["reason"])
        self.assertEqual(rep_b["reusable_files"], [])
        self.assertEqual(rep_b["estimated_savings_bytes"], 0)


class TestSameNameDifferentContent(AnalyzerTestCase):
    def test_conflict_recorded_and_not_merged(self):
        layer_a = self.write_layer(make_tar([("etc/app.conf", "file", b"config-a")]))
        layer_b = self.write_layer(make_tar([("etc/app.conf", "file", b"config-b")]))
        report = analyze_manifest(
            {"images": [self.image("img-a", [layer_a]), self.image("img-b", [layer_b])]}
        )
        rep_a = report["images"]["img-a"]
        rep_b = report["images"]["img-b"]
        # Same name, different content: no dedup, conflict on both sides.
        self.assertEqual(rep_b["reusable_files"], [])
        self.assertEqual(rep_b["estimated_savings_bytes"], 0)
        self.assertEqual(len(rep_a["conflicts"]), 1)
        self.assertEqual(len(rep_b["conflicts"]), 1)
        conflict = rep_b["conflicts"][0]
        self.assertEqual(conflict["path"], "etc/app.conf")
        self.assertIn("different content", conflict["reason"])
        self.assertEqual(conflict["conflicting"][0]["images"], ["img-a"])


class TestPathTraversal(AnalyzerTestCase):
    def test_traversal_entries_recorded_and_excluded(self):
        payload = b"evil"
        raw = make_tar(
            [
                ("../evil.sh", "file", payload),
                ("safe/ok.txt", "file", b"ok"),
            ]
        )
        layer = self.write_layer(raw)
        # A second image contains the same bytes at a safe path; the traversal
        # entry must not act as a dedup source nor be deduplicated itself.
        layer_b = self.write_layer(make_tar([("data/evil.sh", "file", payload)]))
        report = analyze_manifest(
            {"images": [self.image("img-a", [layer]), self.image("img-b", [layer_b])]}
        )
        rep_a = report["images"]["img-a"]
        self.assertEqual(len(rep_a["unsafe_items"]), 1)
        self.assertEqual(rep_a["unsafe_items"][0]["path"], "../evil.sh")
        self.assertIn("unsafe path", rep_a["unsafe_items"][0]["reason"])
        # img-b's identical bytes are not "reused" from the unsafe entry.
        rep_b = report["images"]["img-b"]
        self.assertEqual(rep_b["reusable_files"], [])
        self.assertEqual(rep_b["estimated_savings_bytes"], 0)

    def test_absolute_path_rejected(self):
        raw = make_tar([("/etc/passwd", "file", b"x")])
        layer = self.write_layer(raw)
        report = analyze_manifest({"images": [self.image("img-a", [layer])]})
        rep = report["images"]["img-a"]
        self.assertEqual(len(rep["unsafe_items"]), 1)
        self.assertEqual(rep["reusable_files"], [])


class TestMultiImageSharing(AnalyzerTestCase):
    def test_three_images_share_one_blob(self):
        blob = b"base layer payload" * 32
        layer_a = self.write_layer(make_tar([("base.bin", "file", blob)]))
        layer_b = self.write_layer(make_tar([("copy/base.bin", "file", blob)]))
        layer_c = self.write_layer(make_tar([("other/base.bin", "file", blob)]))
        report = analyze_manifest(
            {
                "images": [
                    self.image("img-a", [layer_a]),
                    self.image("img-b", [layer_b]),
                    self.image("img-c", [layer_c]),
                ]
            }
        )
        images = report["images"]
        self.assertEqual(images["img-a"]["estimated_savings_bytes"], 0)
        self.assertEqual(images["img-b"]["estimated_savings_bytes"], len(blob))
        self.assertEqual(images["img-c"]["estimated_savings_bytes"], len(blob))
        # Both later copies point at the first authoritative copy.
        for name in ("img-b", "img-c"):
            reused = images[name]["reusable_files"][0]
            self.assertEqual(reused["reused_from"]["image"], "img-a")
        summary = report["summary"]
        self.assertEqual(summary["total_estimated_savings_bytes"], 2 * len(blob))
        self.assertEqual(summary["total_reusable_files"], 2)


class TestHardlinks(AnalyzerTestCase):
    def test_hardlink_semantics_preserved(self):
        content = b"hardlinked content"
        raw_a = make_tar(
            [
                ("bin/tool", "file", content),
                ("bin/tool-alias", "hardlink", "bin/tool"),
            ]
        )
        layer_a = self.write_layer(raw_a)
        # img-b stores the same bytes as a plain regular file.
        layer_b = self.write_layer(make_tar([("usr/bin/tool", "file", content)]))
        report = analyze_manifest(
            {"images": [self.image("img-a", [layer_a]), self.image("img-b", [layer_b])]}
        )
        rep_a = report["images"]["img-a"]
        # The hardlink is recorded with its semantics, not as a dedup candidate.
        self.assertEqual(len(rep_a["hardlink_notes"]), 1)
        note = rep_a["hardlink_notes"][0]
        self.assertEqual(note["path"], "bin/tool-alias")
        self.assertEqual(note["target"], "bin/tool")
        self.assertIn("not merged", note["note"])
        hardlinked_paths = {f["path"] for f in rep_a["reusable_files"]}
        self.assertNotIn("bin/tool-alias", hardlinked_paths)
        # Content blob sharing across images is still allowed.
        rep_b = report["images"]["img-b"]
        self.assertEqual(len(rep_b["reusable_files"]), 1)
        self.assertEqual(rep_b["reusable_files"][0]["size"], len(content))

    def test_hardlink_missing_target_is_unsafe(self):
        raw = make_tar([("bin/dangling", "hardlink", "bin/nonexistent")])
        layer = self.write_layer(raw)
        report = analyze_manifest({"images": [self.image("img-a", [layer])]})
        rep = report["images"]["img-a"]
        self.assertEqual(len(rep["unsafe_items"]), 1)
        self.assertIn("hardlink target missing", rep["unsafe_items"][0]["reason"])


class TestDiffIdVerification(AnalyzerTestCase):
    def test_diff_id_mismatch_excluded(self):
        raw = make_tar([("x.txt", "file", b"x")])
        layer = self.write_layer(raw)
        layer["diff_id"] = "sha256:" + "f" * 64
        report = analyze_manifest({"images": [self.image("img-a", [layer])]})
        rep = report["images"]["img-a"]
        self.assertEqual(len(rep["unusable_layers"]), 1)
        self.assertIn("diff_id mismatch", rep["unusable_layers"][0]["reason"])


class TestDirectoriesAndSymlinks(AnalyzerTestCase):
    def test_metadata_entries_not_deduplicated(self):
        raw = make_tar(
            [
                ("etc", "dir", None),
                ("etc/hostname", "file", b"myhost"),
                ("etc/hosts", "symlink", "/run/hosts"),
            ]
        )
        layer = self.write_layer(raw)
        report = analyze_manifest({"images": [self.image("img-a", [layer])]})
        rep = report["images"]["img-a"]
        self.assertEqual(rep["reusable_files"], [])
        self.assertEqual(rep["unsafe_items"], [])
        self.assertEqual(rep["estimated_savings_bytes"], 0)


if __name__ == "__main__":
    unittest.main()

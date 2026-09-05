import json
import unittest
from pathlib import Path


class NarError(ValueError):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, size):
        end = self.offset + size
        if end > len(self.data):
            raise NarError("truncated")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def string(self, maximum=None):
        size = int.from_bytes(self.take(8), "little")
        if maximum is not None and size > maximum:
            raise NarError("length")
        value = self.take(size)
        padding = self.take((-size) % 8)
        if any(padding):
            raise NarError("padding")
        return value


def expect(reader, value):
    if reader.string(32) != value:
        raise NarError("tag")


def decode_node(reader, depth=0):
    if depth >= 64:
        raise NarError("depth")
    expect(reader, b"(")
    expect(reader, b"type")
    kind = reader.string(32)
    if kind == b"regular":
        tag = reader.string(32)
        executable = False
        if tag == b"executable":
            if reader.string(0):
                raise NarError("executable")
            executable = True
            tag = reader.string(32)
        if tag != b"contents":
            raise NarError("tag")
        node = {
            "kind": "regular",
            "executable": executable,
            "contents_hex": reader.string().hex(),
        }
        expect(reader, b")")
        return node
    if kind == b"symlink":
        expect(reader, b"target")
        target = reader.string(4095)
        if not target or b"\0" in target:
            raise NarError("target")
        expect(reader, b")")
        return {"kind": "symlink", "target_hex": target.hex()}
    if kind == b"directory":
        entries = []
        previous = None
        while True:
            tag = reader.string(32)
            if tag == b")":
                return {"kind": "directory", "entries": entries}
            if tag != b"entry":
                raise NarError("tag")
            expect(reader, b"(")
            expect(reader, b"name")
            name = reader.string(255)
            if not name or name in {b".", b".."} or b"/" in name or b"\0" in name:
                raise NarError("name")
            if previous is not None and name <= previous:
                raise NarError("order")
            previous = name
            expect(reader, b"node")
            node = decode_node(reader, depth + 1)
            expect(reader, b")")
            entries.append({"name_hex": name.hex(), "node": node})
    raise NarError("type")


def decode_nar(data):
    reader = Reader(data)
    if reader.string(len(b"nix-archive-1")) != b"nix-archive-1":
        raise NarError("magic")
    node = decode_node(reader)
    if reader.offset != len(data):
        raise NarError("trailing")
    return node


def frame(value):
    return len(value).to_bytes(8, "little") + value + b"\0" * ((-len(value)) % 8)


def encode_node(node):
    result = frame(b"(") + frame(b"type")
    kind = node["kind"]
    if kind == "regular":
        result += frame(b"regular")
        if node["executable"]:
            result += frame(b"executable") + frame(b"")
        result += frame(b"contents") + frame(bytes.fromhex(node["contents_hex"]))
    elif kind == "symlink":
        result += frame(b"symlink") + frame(b"target")
        result += frame(bytes.fromhex(node["target_hex"]))
    elif kind == "directory":
        result += frame(b"directory")
        for entry in node["entries"]:
            result += frame(b"entry") + frame(b"(") + frame(b"name")
            result += frame(bytes.fromhex(entry["name_hex"])) + frame(b"node")
            result += encode_node(entry["node"]) + frame(b")")
    else:
        raise ValueError(kind)
    return result + frame(b")")


def encode_nar(node):
    return frame(b"nix-archive-1") + encode_node(node)


def negative_bytes(vector, manifest):
    if "nested_directories" in vector:
        node = {"kind": "directory", "entries": []}
        for _ in range(vector["nested_directories"]):
            node = {"kind": "directory", "entries": [{"name_hex": "61", "node": node}]}
        return encode_nar(node)
    if "node" in vector:
        return encode_nar(vector["node"])
    data = bytearray(bytes.fromhex(manifest["vectors"][vector["base"]]))
    if "patch" in vector:
        patch = vector["patch"]
        replacement = bytes.fromhex(patch["hex"])
        data[patch["offset"]:patch["offset"] + len(replacement)] = replacement
    if "truncate" in vector:
        del data[-vector["truncate"]:]
    if "append_hex" in vector:
        data.extend(bytes.fromhex(vector["append_hex"]))
    return bytes(data)


class NarVectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).parents[1] / "docs/evidence/nar-vectors.json"
        cls.manifest = json.loads(path.read_text())

    def test_golden_vectors_decode_and_reencode_exactly(self):
        required = {
            "empty_root_file",
            "root_symlink_x",
            "executable_root_abc",
            "empty_root_directory",
            "directory_name_80_empty_file",
            "ordering_divergence_directory",
        }
        self.assertEqual(set(self.manifest["vectors"]), required)
        for name, encoded in self.manifest["vectors"].items():
            data = bytes.fromhex(encoded)
            node = self.manifest["decoded_vectors"][name]
            self.assertEqual(decode_nar(data), node)
            self.assertEqual(encode_nar(node), data)

    def test_malformed_byte_vectors_fail_closed(self):
        required = {
            "duplicate_name",
            "out_of_order_name",
            "bad_length",
            "nonzero_padding",
            "unknown_tag",
            "truncated",
            "trailing_bytes",
            "empty_target",
            "empty_name",
            "dot_name",
            "dotdot_name",
            "slash_name",
            "nul_name",
            "depth_limit",
        }
        self.assertEqual(set(self.manifest["negative_vectors"]), required)
        for vector in self.manifest["negative_vectors"].values():
            with self.assertRaisesRegex(NarError, vector["error"]):
                decode_nar(negative_bytes(vector, self.manifest))

    def test_ordering_counterexample_is_executable(self):
        encoded = self.manifest["vectors"]["ordering_divergence_directory"]
        entries = decode_nar(bytes.fromhex(encoded))["entries"]
        self.assertEqual([entry["name_hex"] for entry in entries], ["61", "612e"])
        git_keys = [bytes.fromhex("612e"), bytes.fromhex("612f")]
        self.assertEqual(sorted(git_keys), git_keys)
        self.assertEqual(self.manifest["ordering_counterexample"]["git_order"], "a. < a/")
        self.assertEqual(self.manifest["ordering_counterexample"]["nar_byte_order"], "a < a.")


if __name__ == "__main__":
    unittest.main()

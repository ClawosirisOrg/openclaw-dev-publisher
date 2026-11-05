"""Explicit, nonauthorizing mount measurement fixture; not an image entrypoint.

The framed config is trusted deployment input only by caller convention. This
module does not authenticate its sender, grant an invocation, or publish.
"""
import json
import os
import sys

from broker.worker import mount_pin


MAX_BODY = 1024
KEYS = ("stage_dev", "stage_ino", "repository", "ref")


def _read_exact(stream, count):
    parts = []
    while count:
        block = stream.read(count)
        if not block:
            raise ValueError("truncated config")
        parts.append(block)
        count -= len(block)
    return b"".join(parts)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate config field")
        result[key] = value
    return result


def read_config(stream):
    """Read one four-byte big-endian length-prefixed canonical UTF-8 object to EOF."""
    size = int.from_bytes(_read_exact(stream, 4), "big")
    if not 0 < size <= MAX_BODY:
        raise ValueError("invalid config size")
    raw = _read_exact(stream, size)
    if stream.read(1):
        raise ValueError("trailing config data")
    body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid constant")))
    if (type(body) is not dict or tuple(body) != KEYS or
            any(type(body[key]) is not int or body[key] < 0 for key in KEYS[:2]) or
            any(type(body[key]) is not str for key in KEYS[2:]) or
            raw != json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")):
        raise ValueError("invalid config")
    return body


def main():
    """Emit only a fixed success token; all denials are silent and nonzero."""
    try:
        if len(sys.argv) != 1:
            return 2
        body = read_config(sys.stdin.buffer)
        mount_pin.build_mount_pin(body["stage_dev"], body["stage_ino"],
                                  worker_uid=os.geteuid(), worker_gid=os.getegid(),
                                  repository=body["repository"], ref=body["ref"])
        sys.stdout.write("MOUNT_PIN_OK")
        return 0
    except Exception:
        # No exception text, input, path, or pin value escapes on denial.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

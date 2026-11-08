"""Rootless-owner mapping and worker self-checks. Not distinct-UID isolation.

Podman 5.8.7 keep-id:uid=1,gid=1 maps worker ID 1 to ID 0 of the
rootless parent namespace (the host owner). Gateway and worker consequently
share host authority. Confidentiality depends on exact mounts, private PID/IPC
namespaces, no capabilities and no runtime/socket/key exposure, NOT numeric UID
inequality. These checks reject the old default-rootless subordinate-ID layout.
"""
import os
import re


def mappings(raw):
    if type(raw) is not str or not 0 < len(raw) <= 4096:
        raise ValueError('invalid identity mapping')
    rows = []
    for line in raw.splitlines():
        if not re.fullmatch(r'\s*[0-9]+[ :]+[0-9]+[ :]+[0-9]+\s*', line):
            raise ValueError('invalid identity mapping')
        parts = re.split(r'[ :]+', line.strip())
        row = tuple(int(part) for part in parts)
        if len(row) != 3 or not 0 < row[2] <= 2**32 or any(v >= 2**32 for v in row[:2]):
            raise ValueError('invalid identity mapping')
        if any(start + row[2] > 2**32 for start in row[:2]):
            raise ValueError('invalid identity mapping')
        rows.append(row)
    if not rows:
        raise ValueError('empty identity mapping')
    for axis in (0, 1):
        ordered = sorted(rows, key=lambda row: row[axis])
        if any(a[axis] + a[2] > b[axis] for a, b in zip(ordered, ordered[1:])):
            raise ValueError('overlapping identity mapping')
    return tuple(rows)


def require_owner_mapping(raw, identity):
    rows = mappings(raw)
    if type(identity) is not int or identity <= 0 or (identity, 0, 1) not in rows:
        raise ValueError('process identity is not the rootless owner')
    return rows


def require_gateway_owner():
    # /proc reports immediate-parent namespace IDs, not bare-host numeric IDs.
    # The Gateway need not and must not change its current process UID.
    for path, identity in (('/proc/self/uid_map', os.geteuid()),
                           ('/proc/self/gid_map', os.getegid())):
        with open(path, encoding='ascii') as stream:
            require_owner_mapping(stream.read(4097), identity)


def require_worker_isolation():
    if (os.geteuid(), os.getegid(), os.getpid()) != (1, 1, 1):
        raise ValueError('worker identity or private PID namespace mismatch')
    for path in ('/proc/self/uid_map', '/proc/self/gid_map'):
        with open(path, encoding='ascii') as stream:
            require_owner_mapping(stream.read(4097), 1)
    values = {}
    with open('/proc/self/status', encoding='ascii') as stream:
        for line in stream:
            key, _, value = line.partition(':')
            if key in ('CapEff', 'CapPrm', 'CapBnd', 'NoNewPrivs'):
                values[key] = value.strip()
    if (set(values) != {'CapEff', 'CapPrm', 'CapBnd', 'NoNewPrivs'} or
            values['NoNewPrivs'] != '1' or
            any(int(values[key], 16) != 0 for key in ('CapEff', 'CapPrm', 'CapBnd'))):
        raise ValueError('worker privileges mismatch')
    # Reject a host /proc bind even if namespace configuration looked correct.
    own, proc = os.stat('/'), os.stat('/proc/1/root')
    if (own.st_dev, own.st_ino) != (proc.st_dev, proc.st_ino):
        raise ValueError('worker proc namespace mismatch')
    for name in os.listdir('/proc/self/fd'):
        if name in ('0', '1', '2'):
            continue
        try:
            os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError:  # listdir's transient directory FD
            continue
        raise ValueError('unexpected inherited worker descriptor')

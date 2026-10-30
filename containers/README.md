# Inert worker image recipe (offline, not a deployment)

`Containerfile` copies only the eight explicitly named Python files from
`broker/worker` and `broker/transport`. Python modules are mode 0444; the
strict askpass executable is mode 0555. The image does not
copy tests, the repository checkout, Git objects, a signer public/private key,
application key, token, credential, private configuration, or any host/socket
identifier. The numeric image user is UID/GID 1 and the default entrypoint is
`/usr/bin/false`; neither creates an authenticated or usable publisher.
`askpass.py` is not the image entrypoint and cannot obtain a token without a
separately protected FD.

## Offline review and build procedure (operator-only; do not run as activation)

Review the eight source files, the Containerfile, and the exact *local* base
image first. The base must provide the intended Python/Git/SSH dependencies and
`/usr/bin/false`; audit its contents and inherited metadata independently. Set
`BASE_IMAGE` to the operator-approved immutable reference ending in
`@sha256:` followed by exactly 64 lowercase hexadecimal digits. It has no
default. Containerfile syntax cannot validate the reference *before* `FROM`
resolves it; this input check must precede any build, even an offline one.
Do not substitute a tag, short digest, or an agent-supplied value.

From the repository root, an operator can prepare a disposable **minimal**
context and print its exact whitelist without building or pulling anything:

```bash
set -euo pipefail
: "${BASE_IMAGE:?set an operator-approved local base reference with a sha256 digest}"
[[ "$BASE_IMAGE" == *@sha256:* ]]
digest="${BASE_IMAGE##*@sha256:}"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]]
ctx="$(mktemp -d)"
trap 'rm -rf -- "$ctx"' EXIT
python3 - "$ctx" <<'PY'
import hashlib
from pathlib import Path
import shutil
import stat
import sys

context = Path(sys.argv[1])
paths = (
    'containers/Containerfile',
    'broker/worker/__init__.py',
    'broker/worker/claim.py',
    'broker/worker/capture_once.py',
    'broker/worker/handoff.py',
    'broker/worker/verifier.py',
    'broker/transport/askpass.py',
    'broker/transport/git_adapter.py',
    'broker/transport/one_shot.py',
)
for name in paths:
    source = Path(name)
    mode = source.lstat().st_mode
    if not stat.S_ISREG(mode) or source.stat().st_nlink != 1:
        raise SystemExit(f'not an ordinary standalone file: {name}')
    target = context / (name.removeprefix('containers/') if name.startswith('containers/') else name)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o444)
    if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(target.read_bytes()).digest():
        raise SystemExit(f'source changed during staging: {name}')
expected = {name.removeprefix('containers/') for name in paths}
actual = {str(p.relative_to(context)) for p in context.rglob('*') if not p.is_dir()}
if actual != expected:
    raise SystemExit(f'context whitelist mismatch: {sorted(actual ^ expected)}')
print('Context files (no build):')
print('\n'.join(sorted(actual)))
PY
```

Inspect that printout and the staged files. To perform a **separately
authorized** offline image build in the same shell, with the pinned base
already present locally, an operator may then use:

```bash
podman image exists "$BASE_IMAGE"  # local presence only; no pull
podman build --pull=never --network=none --build-arg BASE_IMAGE="$BASE_IMAGE" \
  -f "$ctx/Containerfile" "$ctx"
```

Do not commit a built image identifier or digest as the image lock here. The
approved image lock, base provenance and deployment manifest are **private
deployment artifacts**, independently recorded and verified by the operator.
Building an image does not activate it or authorize a launch, token issuance,
Git access or publication. `--network=none` above is a build-time setting;
network-none/egress denial, limited and correctly owned mounts, read-only
filesystem, protected `/proc`, distinct UID isolation and image identity are
**launch-time guarantees**, not claims established by this Containerfile.
There is no launch command here. Keep all host paths, socket identifiers,
repository grants, signer keys and credentials out of the image and public
documentation.

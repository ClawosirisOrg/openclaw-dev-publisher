"""Offline, credential-free one-claim object capture fixture. No publication authority.

The caller must supply a private one-way framed pipe, a dedicated exclusive
stage pin, a separately trusted source bind, and a trusted signer config. This
module cannot authenticate the issuer, source ownership, image, or runtime; a
separately reviewed final guard is required before any real effect. In
particular, same-UID actors able to mutate the protected stage or source bind
are outside this fixture's trust boundary. Never retry an invocation with a
new stage after an ambiguous failure. Failed captures remain partial and the
entire stage must be quarantined/discarded by its owner.
"""
from dataclasses import dataclass
import os
import stat

from . import claim, handoff, verifier

CHILD = "capture"


@dataclass(frozen=True)
class SourceBind:
    """Deploy-only source root identity, never obtained from the claim frame."""
    path: str
    dev: int
    ino: int
    mnt_id: int


def _open_source(bind):
    if (type(bind) is not SourceBind or
            any(type(v) is not int or v < 0 for v in
                (bind.dev, bind.ino, bind.mnt_id))):
        raise ValueError("invalid trusted source bind")
    # The same nofollow, component-wise path walk as the protected stage.
    path = bind.path
    if (type(path) is not str or not path.startswith("/") or path == "/" or
            any(part in ("", ".", "..") for part in path.split("/")[1:])):
        raise ValueError("invalid trusted source path")
    fd = os.open("/", claim.DIR_FLAGS)
    try:
        for part in path.split("/")[1:]:
            child = os.open(part, claim.DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or
                (info.st_dev, info.st_ino, claim._mount_id(fd)) !=
                (bind.dev, bind.ino, bind.mnt_id)):
            raise ValueError("source bind pin mismatch")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _same_child(stage, child):
    """Fail closed if the new child name is no longer the captured inode."""
    current = os.open(CHILD, claim.DIR_FLAGS, dir_fd=stage)
    try:
        original, named = os.fstat(child), os.fstat(current)
        if (not stat.S_ISDIR(original.st_mode) or
                original.st_uid != os.geteuid() or
                stat.S_IMODE(original.st_mode) != 0o700 or
                (original.st_dev, original.st_ino, claim._mount_id(child)) !=
                (named.st_dev, named.st_ino, claim._mount_id(current))):
            raise ValueError("capture child changed")
    finally:
        os.close(current)


def capture_once(context_fd, deploy, source_bind, config):
    """Claim exactly once, then capture only verified objects into a fresh child.

    Owns and closes context_fd via claim_once, including on claim failure.
    Successful return is non-authorizing evidence, never a publish permit.
    No expected tree, verifier override, signer start, network, or CLI.
    """
    receipt = claim.claim_once(context_fd, deploy)
    # Never accept context or expected object data from any other argument.
    # These trusted pins are checked *after* the claim, so failures spend it.
    if type(config) is not verifier.DeployConfig:
        raise ValueError("trusted signer config required")
    config.__post_init__()
    if receipt["repository"] != config.repository or receipt["ref"] != config.base_ref:
        raise ValueError("claim and signer deployment mismatch")
    invocation = verifier.Invocation(receipt["sha"], receipt["branch"], receipt["base"],
                                     receipt["model"], receipt["thinking"])
    invocation.validate(config)
    source = _open_source(source_bind)
    try:
        stage = claim._open_stage(deploy)
        try:
            # claim_once leaves .claim in the parent, while handoff.capture
            # insists on an entirely empty destination. Use a fixed, fresh,
            # exclusive child and never remove the claim marker on failure.
            os.mkdir(CHILD, 0o700, dir_fd=stage)
            child = os.open(CHILD, claim.DIR_FLAGS, dir_fd=stage)
            try:
                _same_child(stage, child)
                # Both paths resolve via retained descriptors; mutable source
                # and stage pathnames cannot redirect the copy. A trailing
                # slash makes the procfd link an intermediate path component;
                # handoff reopens the resolved directory with O_NOFOLLOW.
                path = lambda fd: f"/proc/{os.getpid()}/fd/{fd}/"
                facts = handoff.capture(path(source), path(child), invocation, config)
                _same_child(stage, child)
                rebound = _open_source(source_bind)
                try:
                    if (os.fstat(rebound).st_dev, os.fstat(rebound).st_ino) != (
                            os.fstat(source).st_dev, os.fstat(source).st_ino):
                        raise ValueError("source changed")
                finally:
                    os.close(rebound)
                # The originally pinned stage must still be reachable by its
                # trusted deploy path before any facts can be returned.
                reopened = claim._open_stage(deploy)
                try:
                    if (os.fstat(reopened).st_dev, os.fstat(reopened).st_ino) != (
                            os.fstat(stage).st_dev, os.fstat(stage).st_ino):
                        raise ValueError("stage changed")
                finally:
                    os.close(reopened)
                return {"claim": receipt, "capture": facts, "publishable": False,
                        "provenance_authenticated": False, "authorization_claimed": False}
            finally:
                os.close(child)
        finally:
            os.close(stage)
    finally:
        os.close(source)


def main(*_args, **_kwargs):
    raise RuntimeError("capture entrypoint disabled: issuer and final guard unproven")


if __name__ == "__main__":
    main()

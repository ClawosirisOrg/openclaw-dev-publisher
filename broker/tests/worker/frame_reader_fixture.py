"""Offline test fixture: read fd 3, never call the disabled production CLI."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from broker.worker.claim import DeploymentPin, read_frame  # noqa: E402


# Independent deployment pin, not derived from bytes supplied on the pipe.
PIN = DeploymentPin(stage_path="/unused-test-stage", stage_dev=0, stage_ino=0,
                    stage_mnt_id=0, worker_uid=0,
                    repository="fixture/repository", ref="refs/heads/main")


try:
    body = read_frame(3, PIN)
except ValueError as exc:
    # No frame, IDs, or input bytes go to stdout (including on errors).
    print(json.dumps({"ok": False, "error": str(exc)}))
    sys.exit(2)
else:
    print(json.dumps({"ok": True, "same_id": body["transactionId"] == body["claimId"],
                      "repository": body["repository"], "ref": body["ref"],
                      "model": body["model"], "thinking": body["thinking"]}))

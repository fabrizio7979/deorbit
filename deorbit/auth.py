"""Robot identity and login verification."""

import base64
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass(frozen=True)
class RobotId:
    """Registry key for a robot. Both parts are lowercase, as in the signed login string."""

    vendor: str
    serial: str  # the board serial, not the consumer-facing robot serial

    def __str__(self) -> str:
        return f"{self.vendor}/{self.serial}"


class LoginRejected(Exception):
    def __init__(self, code: int, reason: str) -> None:
        super().__init__(reason)
        self.code = code


def _key_files(directory: Path) -> Iterator[tuple[RobotId, Path]]:
    """Each key file of the registry, ``<directory>/<vendor>/<board serial>.pem``, with the robot it is of."""
    for path in sorted(directory.glob("*/*.pem")):
        yield RobotId(path.parent.name.lower(), path.stem.lower()), path


def load_keys(directory: Path) -> dict[RobotId, rsa.RSAPublicKey]:
    """Load the robot registry from ``<directory>/<vendor>/<board serial>.pem``."""
    keys = {}
    for robot, path in _key_files(directory):
        key = serialization.load_pem_public_key(path.read_bytes())
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError(f"{path}: not an RSA public key")
        keys[robot] = key
    return keys


def delete_key(directory: Path, robot: RobotId) -> None:
    """Remove the robot's key file from the registry, or each of them where names that differ only in case gave it several.

    The files are found the way ``load_keys`` finds them, by listing the
    directory, so here too no path is built from the name of a robot.
    """
    for found, path in _key_files(directory):
        if found == robot:
            path.unlink(missing_ok=True)


class Authenticator:
    """Checks login frames against the registry.

    With ``keys=None`` nothing is verified and every well-formed login is
    accepted. ``max_clock_skew=0`` turns off the timestamp window, and replay
    protection with it.
    """

    def __init__(self, keys: dict[RobotId, rsa.RSAPublicKey] | None, max_clock_skew: float) -> None:
        self._keys = keys
        self._max_clock_skew = max_clock_skew
        self._seen: dict[tuple[RobotId, str], float] = {}  # login tuple -> expiry

    @property
    def enabled(self) -> bool:
        return self._keys is not None

    def forget(self, robot: RobotId) -> None:
        """Take the robot's key out of the registry, so that a login of its is refused from now on."""
        if self._keys is not None:
            self._keys.pop(robot, None)

    def authenticate(self, login: dict) -> RobotId:
        fields = [login.get(name) for name in ("vendor", "serial", "datetime", "signature")]
        if not all(isinstance(value, str) and value and value.isprintable() for value in fields):
            raise LoginRejected(400, "malformed login")
        vendor, serial, stamp, signature = fields
        robot = RobotId(vendor.lower(), serial.lower())
        if self._keys is None:
            return robot

        key = self._keys.get(robot)
        if key is None:
            raise LoginRejected(401, f"no public key registered for {robot}")
        message = f"{robot.vendor}\n{robot.serial}\n{stamp}".encode()
        try:
            key.verify(
                base64.b64decode(signature, validate=True),
                message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (ValueError, InvalidSignature):
            raise LoginRejected(401, "bad signature") from None
        if self._max_clock_skew:
            self._check_fresh(robot, stamp)
        return robot

    def _check_fresh(self, robot: RobotId, stamp: str) -> None:
        try:
            signed_at = datetime.fromisoformat(stamp)
        except ValueError:
            raise LoginRejected(401, "unparseable datetime") from None
        if signed_at.tzinfo is None:
            signed_at = signed_at.replace(tzinfo=timezone.utc)
        skew = abs((datetime.now(timezone.utc) - signed_at).total_seconds())
        if skew > self._max_clock_skew:
            raise LoginRejected(401, f"timestamp is {skew:.0f}s off, limit is {self._max_clock_skew:g}s")

        now = time.monotonic()
        self._seen = {token: expiry for token, expiry in self._seen.items() if expiry > now}
        if (robot, stamp) in self._seen:
            raise LoginRejected(401, "replayed login")
        # A timestamp up to one window ahead stays acceptable for two windows.
        self._seen[robot, stamp] = now + 2 * self._max_clock_skew

"""Robot-to-server services, routed by ``to.service``.

A handler takes the store, the robot and the request body, and returns
``(code, body)``, or ``None`` when the robot expects no answer. The handlers
of ``peer.state`` and ``maps.create`` store what they are sent; every other
service gets the minimal reply that keeps the robot happy. The event log is not
kept here: the session adds a message to it before calling the handler.
"""

import logging
from collections.abc import Callable
from typing import Any

from .auth import RobotId
from .store import Store

log = logging.getLogger(__name__)

Reply = tuple[int, Any] | None


def _no_reply(store: Store, robot: RobotId, body: Any) -> Reply:
    return None


def _peer_state(store: Store, robot: RobotId, body: Any) -> Reply:
    if isinstance(body, dict):
        store.save_state(robot, body)
    else:
        # Nothing to store, and the last good state is worth more than a blank.
        log.warning("[%s] peer.state without a state object: not saved", robot)
    return None


def _robots_link(store: Store, robot: RobotId, body: Any) -> Reply:
    return 201, {}


def _firmware_check(store: Store, robot: RobotId, body: Any) -> Reply:
    # Any code other than 200 means "no update".
    return 404, {}


def _maps_create(store: Store, robot: RobotId, body: Any) -> Reply:
    # 201 says the map is kept, so it is answered only once it is in the file.
    # The robot takes any other code for a failed upload.
    if not isinstance(body, dict):
        log.warning("[%s] maps.create without a map object: not saved", robot)
        return 400, {}
    if not store.save_map(robot, body):
        return 500, {}
    # Never a floor plan: on true the robot promotes the map by itself.
    return 201, {"floorplan": False}


def _logs_list_files(store: Store, robot: RobotId, body: Any) -> Reply:
    # No upload URLs: the robot has nothing to PUT.
    return 200, {"urls": []}


def _logs_update_status(store: Store, robot: RobotId, body: Any) -> Reply:
    return 200, {}


SERVICES: dict[str, Callable[[Store, RobotId, Any], Reply]] = {
    "peer.state": _peer_state,
    "robots.error_codes": _no_reply,
    # A request on the wire, but the robot never waits for the response.
    "robots.notify": _no_reply,
    "robots.link": _robots_link,
    "firmware.check": _firmware_check,
    "maps.create": _maps_create,
    "logs.list_files": _logs_list_files,
    "logs.update_status": _logs_update_status,
}

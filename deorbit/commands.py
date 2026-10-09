"""What the web UI can send a robot: its commands and the changes to its schedule, each an ability invoked through ``Session.call``."""

import json
import re

# By the name a robot's state gives the command under ``available_commands``:
# the ability to invoke and what is sent with it, which is nothing for all but
# the first.
#
# ``cleaning.start`` takes ``runs``, at least one, each with its ``settings``
# and its ``map`` (section 6.1 of the spec). A map of ``None`` is a cleaning on
# no saved floor plan, the only kind there is to ask for while this server
# keeps no floor plans. The mode may be eco, turbo, auto or max and the
# navigation mode normal or gentle; these two are the ones a robot gave for a
# run started from its own button.
COMMANDS: dict[str, tuple[str, dict]] = {
    "start": ("cleaning.start", {"runs": [{"map": None, "settings": {"mode": "eco", "navigation_mode": "normal"}}]}),
    "pause": ("cleaning.pause", {}),
    "resume": ("cleaning.resume", {}),
    "cancel": ("cleaning.cancel", {}),
    "return_to_base": ("navigation.return_to_base", {}),
}

# What an event of a robot's schedule may name (section 6.2 of the spec, and
# 6.1 for the settings of a run). The page's script lists the same.
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MODES = ("eco", "turbo", "auto", "max")
NAVIGATION_MODES = ("normal", "gentle")

_ID = re.compile(r"[0-9]+")
_TIME = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")


def _fields(given: object, where: str, *names: str) -> list:
    """The values of the fields ``names`` of ``given``, which has to be an object of just those."""
    if not isinstance(given, dict) or set(given) != set(names):
        raise ValueError(f"{where} must be an object of {', '.join(names)} and nothing else")
    return [given[name] for name in names]


def _among(value: object, allowed: tuple[str, ...], where: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{where} must be one of {', '.join(allowed)}")
    return value


def _id(value: object, where: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{where} must be a string of digits")
    return value


def _run(given: object, where: str) -> dict:
    """A ``CleaningRun`` of the spec, made of the one ``given``."""
    settings, place = _fields(given, where, "settings", "map")
    mode, navigation = _fields(settings, f"{where}.settings", "mode", "navigation_mode")
    run = {
        "settings": {
            "mode": _among(mode, MODES, f"{where}.settings.mode"),
            "navigation_mode": _among(navigation, NAVIGATION_MODES, f"{where}.settings.navigation_mode"),
        },
        "map": None,
    }
    if place is not None:
        rank, track, nogo = _fields(place, f"{where}.map, unless null,", "rank_id", "track_id", "nogo_enabled")
        if not isinstance(rank, str) or not rank:
            raise ValueError(f"{where}.map.rank_id must be a string that is not empty")
        if track is not None and (not isinstance(track, str) or not track):
            raise ValueError(f"{where}.map.track_id must be null or a string that is not empty")
        if not isinstance(nogo, bool):
            raise ValueError(f"{where}.map.nogo_enabled must be true or false")
        run["map"] = {"rank_id": rank, "track_id": track, "nogo_enabled": nogo}
    return run


def _event(given: object, *, known: bool) -> dict:
    """An event of a schedule, made of the one ``given``: with its ``id`` when it is ``known`` to the robot, without one when new.

    Nothing of ``given`` is passed on as it came: the event holds what the spec
    gives one and no more, each value checked.
    """
    names = ("enabled", "days", "time", "command")
    if known:
        number, *values = _fields(given, "event", "id", *names)
        event = {"id": _id(number, "event.id")}
    else:
        values = _fields(given, "event", *names)
        event = {}
    enabled, days, time, command = values
    if not isinstance(enabled, bool):
        raise ValueError("event.enabled must be true or false")
    # The spec allows a list of no days. What a robot makes of one is not known, so none is sent.
    if not isinstance(days, list) or not days or any(not isinstance(day, str) or day not in DAYS for day in days):
        raise ValueError(f"event.days must be a list of one or more of {', '.join(DAYS)}")
    if not isinstance(time, str) or not _TIME.fullmatch(time):
        raise ValueError("event.time must be a time from 00:00 to 23:59")
    ability, runs = _fields(command, "event.command", "ability", "runs")
    if ability != "cleaning.start":
        raise ValueError("event.command.ability must be cleaning.start")
    if not isinstance(runs, list) or not runs:
        raise ValueError("event.command.runs must be a list of one or more runs")
    runs = [_run(run, f"event.command.runs[{n}]") for n, run in enumerate(runs)]
    # More runs than one are the zones of one floor plan (section 6.1).
    maps = [run["map"] for run in runs]
    if len(runs) > 1 and (None in maps or len({place["rank_id"] for place in maps}) > 1):
        raise ValueError("event.command.runs, when more than one, must each have a map of the same rank_id")
    return {
        **event,
        "enabled": enabled,
        "days": [day for day in DAYS if day in days],
        "time": time,
        "command": {"ability": ability, "runs": runs},
    }


def scheduling(action: str, number: str, event: str) -> tuple[str, dict]:
    """The ability for an action on a robot's schedule and what is sent with it, or a ``ValueError`` that says what is wrong.

    ``number`` is the ``id`` of the event to delete, and ``event`` the JSON of
    the one to add or of the one to put in place of that whose ``id`` it has.
    The spec gives ``scheduling.add`` and ``scheduling.update`` one body, with
    an ``id`` that may be left out to make a new event; here ``add`` never
    sends one and ``update`` always does.
    """
    if action == "show":
        return "scheduling.show", {}
    if action == "delete":
        return "scheduling.delete", {"id": _id(number, "id")}
    if action in ("add", "update"):
        try:
            given = json.loads(event)
        except (ValueError, RecursionError):  # the second for brackets nested deeper than Python follows them
            raise ValueError("event must be JSON") from None
        return f"scheduling.{action}", {"event": _event(given, known=action == "update")}
    raise ValueError("action must be one of show, add, update, delete")

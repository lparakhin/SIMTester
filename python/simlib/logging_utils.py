"""Port of de.srlabs.simlib.LoggingUtils."""

import inspect


def format_debug_message(message: str) -> str:
    """Prefix a message with [ClassName, method_name] of the calling function."""
    frame = inspect.stack()[1]
    class_name = frame.frame.f_globals.get("__name__", "?")
    method_name = frame.function
    return f"[{class_name}, {method_name}] {message}"

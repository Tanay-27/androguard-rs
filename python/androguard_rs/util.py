"""``androguard.util`` stand-ins."""


def set_log(level: str) -> None:
    """androguard's ``set_log(level)`` configures loguru for androguard's own
    logging. androguard_rs logs nothing, so this does nothing."""
    return None

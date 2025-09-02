from typing import Callable, Iterable, List
from ._core import HeaderLite, next_bits_window  # type: ignore

__all__ = [
    "HeaderLite",
    "next_bits_window",
    "filter_last_n_for_algo",
]


def filter_last_n_for_algo(chain: Iterable[HeaderLite], N: int,
                           algo_from_version: Callable[[int], int],
                           algo_id: int) -> List[HeaderLite]:
    """Return the last N headers from `chain` that belong to `algo_id`, preserving order.
    The `chain` must be ordered from oldest to newest.
    """
    buf: List[HeaderLite] = []
    for h in chain:
        if algo_from_version(int(h.version)) == algo_id:
            buf.append(h)
    return buf[-N:]

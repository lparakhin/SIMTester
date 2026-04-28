"""Python file scanner over 2-byte FIDs using pluggable selector."""

from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class SimCardFileView:
    file_id: str
    file_type: str
    child_dfs: int = 0
    child_efs: int = 0


Selector = Callable[[str], SimCardFileView]


class FileScanner:
    user_defined_reserved_ids: list[str] = []

    @classmethod
    def scan_sim_from_path(cls, starting_df: str, select_path: Selector, break_after_counts_match: bool = False, lazy_scan: bool = False) -> dict[str, SimCardFileView]:
        reserved = {"3F00", "3FFF", "7FFF", "FFFF", *cls.user_defined_reserved_ids}
        results: dict[str, SimCardFileView] = {}
        current = select_path(starting_df)
        results[starting_df] = current
        found_df, found_ef = 0, 0

        for i in range(0x10000):
            fid = f"{i:04X}"
            if fid in reserved:
                continue
            if lazy_scan:
                lvl = len(starting_df) // 4
                if lvl == 1 and not (0x2F00 <= i <= 0x2FFF or 0x7F00 <= i <= 0x7FFF):
                    continue
                if lvl == 2 and not (0x5F00 <= i <= 0x5FFF or 0x6F00 <= i <= 0x6FFF):
                    continue
                if lvl == 3 and not (0x4F00 <= i <= 0x4FFF):
                    continue
            try:
                entry = select_path(starting_df + fid)
            except FileNotFoundError:
                continue
            results[starting_df + fid] = entry
            if entry.file_type in {"EF", "INTERNAL_EF"}:
                found_ef += 1
            elif entry.file_type == "DF":
                found_df += 1
            if break_after_counts_match and found_df >= current.child_dfs and found_ef >= current.child_efs:
                break
        return results

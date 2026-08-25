"""Port of de.srlabs.simtester.FileScanner."""

from __future__ import annotations

from simlib import config
from simlib import debug as _debug
from simlib import hex_toolkit as hx
from simlib.channel_handler import ChannelHandler
from simlib.common_file_reader import get_aids
from simlib.file_management import FileManagement, FileNotFoundOnCard
from simlib.file_mapping import ISIMCardFileMapping, MFSimCardFileMapping, SimCardFileMapping, USIMCardFileMapping
from simlib.logging_utils import format_debug_message
from simlib.sim_card_file import SimCardFile

user_defined_reserved_ids: list[str] = []


def _scan_sim_from_path(starting_df: str, break_after_counts_match: bool, lazy_scan: bool,
                         above_level_files: list[str] | None = None, same_level_files: list[str] | None = None,
                         scan_aid: bool = False) -> dict:
    above_level_files = above_level_files or []
    same_level_files = same_level_files or []

    dir_scan = [starting_df]
    results: dict = {}

    reserved_values = ["3F00", "3FFF", "7FFF", "FFFF"] + list(user_defined_reserved_ids)

    results_fids = [starting_df[-4:]]

    if _debug.DEBUG and user_defined_reserved_ids:
        print(format_debug_message(f"File scanning added the following user-defined reserved file IDs: {user_defined_reserved_ids}"))

    print(f"Reserved values are: {reserved_values}")
    print(f"FIDs from above level: {above_level_files}")
    print(f"FIDs from same level: {same_level_files}")

    current_dir = dir_scan[0]

    if scan_aid:
        current = FileManagement.select_file_by_path(current_dir)
    else:
        current = FileManagement.select_path(current_dir)

    has_dfs = current.get_number_of_child_dfs()
    has_efs = current.get_number_of_child_efs()

    print(f"[{current_dir}] Should have {has_dfs} directories and {has_efs} files.")

    results[current_dir] = current

    found_dfs = 0
    found_efs = 0
    last_select_successful = False

    for i in range(0x10000):  # 0xFFFF inclusive
        if lazy_scan:
            level = len(current_dir) // 4
            if level == 1:
                if not (0x2F00 <= i <= 0x2FFF) and not (0x7F00 <= i <= 0x7FFF):
                    continue
            elif level == 2:
                if not (0x5F00 <= i <= 0x5FFF) and not (0x6F00 <= i <= 0x6FFF):
                    continue
            elif level == 3:
                if not (0x4F00 <= i <= 0x4FFF):
                    continue

        file_id = f"{i:04X}"

        if file_id in reserved_values or file_id in above_level_files or file_id in same_level_files:
            if _debug.DEBUG:
                print(format_debug_message(f"======= RESERVED VALUE {file_id} FOUND, SKIPPING!! ======="))
            continue

        if last_select_successful or scan_aid:
            file_path = current_dir + file_id
        else:
            file_path = file_id

        if i % 100 == 0:
            print(f"[{current_dir}] currently checking: {file_id}")

        try:
            if scan_aid:
                file = FileManagement.select_file_by_path(file_path)
            else:
                file = FileManagement.select_path(file_path)

            # We found a case where selecting 7F21 returned FID 7F20 in the response.
            # If we already have that FID in our results, ignore it.
            if file.get_file_id() in results_fids:
                results_fids.append(file_id)
                continue
            elif file.get_file_id() != file_id:
                raise RuntimeError(f"The selected FID ({file_id}) does not match with the file FID ({file.get_file_id()})")

            print(f"[{current_dir}] File FOUND, id: {file.get_file_id()}, type: {file.get_file_type_name()}")

            if file.get_file_type() in (SimCardFile.EF, SimCardFile.INTERNAL_EF):
                found_efs += 1
                results[current_dir + file_id] = file
                results_fids.append(file_id)
                if _debug.DEBUG:
                    print(f"[{current_dir}] Found EFs: {found_efs}/{has_efs}")
            elif file.get_file_type() == SimCardFile.DF:
                found_dfs += 1
                dir_scan.append(current_dir + file_id)
                results[current_dir + file_id] = file
                results_fids.append(file_id)
                print(f"Found FIDs are: {results_fids}")
                if _debug.DEBUG:
                    print(format_debug_message(f"[{current_dir}] Found DFs: {found_dfs}/{has_dfs}"))
            elif file.get_file_type() == SimCardFile.ADF:
                print(f"ADF found: {file_id}")
                user_defined_reserved_ids.append(file_id)
            else:
                raise RuntimeError(f"File is not EF or DF. It is: {file.get_file_type_name()}. File path: {file_path}")

            if break_after_counts_match and found_efs == has_efs and found_dfs == has_dfs:
                print(f"[{current_dir}] Already got all DFs and EFs, no point in scanning any further")
                break

            last_select_successful = True

        except FileNotFoundOnCard:
            last_select_successful = False

    print(f"[{current_dir}] STATUS: found DFs: {found_dfs}/{has_dfs}, found EFs: {found_efs}/{has_efs}")
    print(f"Files found: {results_fids}")
    print()
    dir_scan.remove(current_dir)

    while dir_scan:
        results.update(_scan_sim_from_path(dir_scan.pop(0), break_after_counts_match, lazy_scan, same_level_files, results_fids, scan_aid))

    return results


def get_fid_for_aid(aid: str) -> str | None:
    print()
    print(f"\033[96mSearch for FID of AID {aid}\033[0m")

    reserved_values = ["3F00", "3FFF", "7FFF", "FFFF"]

    try:
        fid = FileManagement.select_aid(hx.from_string(aid))
    except FileNotFoundOnCard:
        return None

    if fid is not None:
        return hx.to_string(fid)

    for i in range(0x10000):
        file_id = f"{i:04X}"

        if file_id in reserved_values:
            continue

        if i % 500 == 0:
            print(f"Currently checking: {file_id}")

        try:
            file = FileManagement.select_path(file_id)
            if file.get_file_type() == SimCardFile.ADF:
                return file_id
        except FileNotFoundOnCard:
            pass

    return None


def scan_sim(break_after_counts_match: bool, lazy_scan: bool, writer):
    final_results = []
    aids: list[str] = []

    writer.write_raw_line("# path,type,size,name,humanly_readable")

    if config.third_gen_apdu:
        ChannelHandler.get_instance().reset()
        aids = get_aids()
        for aid in aids:
            fid = get_fid_for_aid(aid)
            if fid is None:
                print("\033[96mNo FID found. Maybe you want to manually check it\033[0m")
            else:
                print(f"FID found: {fid}")
            user_defined_reserved_ids.append(fid)
        ChannelHandler.get_instance().reset()

    print("")
    print("\033[96mReading files from MF\033[0m")
    scan_file_results = _scan_sim_from_path("3F00", break_after_counts_match, lazy_scan, scan_aid=False)
    final_results.extend(MFSimCardFileMapping().get_mapped_name_and_description(scan_file_results))

    if config.third_gen_apdu:
        for aid in aids:
            print(f"\033[96mSelecting the AID {aid}\033[0m")
            try:
                FileManagement.select_aid(hx.from_string(aid))
            except FileNotFoundOnCard as e:
                print(e)
                continue

            scan_file_results = _scan_sim_from_path("7FFF", break_after_counts_match, lazy_scan, scan_aid=True)

            # https://www.etsi.org/deliver/etsi_ts/101200_101299/101220/12.00.00_60/ts_101220v120000p.pdf (Table E.1)
            if aid.startswith("A0000000871002"):
                final_results.extend(USIMCardFileMapping().get_mapped_name_and_description(scan_file_results, aid))
            elif aid.startswith("A0000000871004"):
                final_results.extend(ISIMCardFileMapping().get_mapped_name_and_description(scan_file_results, aid))
            else:
                final_results.extend(SimCardFileMapping().get_mapped_name_and_description(scan_file_results, aid))

    for file in final_results:
        print(f"{file.get_file_path():<20} {file.get_file_size():4d} {file.get_file_name():<15} {file.get_file_description()}")
        writer.write_raw_line(
            f"{file.get_file_path()},{file.get_file_type_name()},{file.get_file_size()},{file.get_file_name()},{file.get_file_description()}")


#!/usr/bin/env python3
"""
Based on https://stackoverflow.com/a/36113168/300783
and forked from https://gist.github.com/tfeldmann/fc875e6630d11f2256e746f67a09c1ae .

Modified for Python3 with some small code improvements.
updated original script to contain:
1. error logging
2. storing output in csv file with file,foldername, duplicates details
3. commandline 
4. output folder 
5. option to rename duplicates to delete them afterwards.
Fast duplicate file finder with logging, timestamped CSV output, and optional duplicate renaming.

Usage:
    duplicates.py <folder> [<folder> ...]
                  [--store-dir STORE]
                  [--hash {sha1,sha256,blake2b}]
                  [--chunk-size BYTES]
                  [--log-level {DEBUG,INFO,WARNING,ERROR}]
                  [--rename-duplicates]
                  [--prefix PREFIX]
                  [--dry-run]
                  [--keep-strategy {first,mtime_oldest,mtime_newest}]

Defaults:
- NO renaming unless --rename-duplicates is provided.
- CSV filenames are timestamped to avoid overwriting previous results.

Outputs:
- store/duplicates.log
- store/duplicates-YYYY-MM-DD_HH-MM-SS.csv
"""

import os
import sys
import csv
import argparse
import logging
import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple, Iterable
from datetime import datetime


# -----------------------
# Logging setup utilities
# -----------------------

def setup_store_dir(store_dir: str) -> None:
    """Ensure the store directory exists."""
    try:
        os.makedirs(store_dir, exist_ok=True)
    except Exception as e:
        print(f"ERROR: Could not create store directory '{store_dir}': {e}", file=sys.stderr)
        raise


def setup_logging(store_dir: str, level: str = "INFO") -> logging.Logger:
    """Configure logging to file and console."""
    logger = logging.getLogger("duplicates")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False  # avoid duplicate logs if root handlers exist

    # Clear existing handlers (in case of repeated invocation)
    logger.handlers.clear()

    log_path = os.path.join(store_dir, "duplicates.log")

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # File handler
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(getattr(logging, level.upper(), logging.INFO))
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(getattr(logging, level.upper(), logging.INFO))
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.info("Initialized logging.")
    logger.info(f"Log file: {log_path}")
    return logger


# -----------------------
# Hashing helpers
# -----------------------

def chunk_reader(fobj, chunk_size: int = 1024) -> Iterable[bytes]:
    """Generator that reads a file in chunks of bytes."""
    while True:
        chunk = fobj.read(chunk_size)
        if not chunk:
            return
        yield chunk


def get_hash(filename: str, first_chunk_only: bool = False,
            hash_algo=hashlib.sha1, chunk_size: int = 65536) -> bytes:
    """
    Compute hash for a file.
    - If first_chunk_only=True, hash only the first 1024 bytes (fixed).
    - Else, hash the entire file in chunks of 'chunk_size'.
    """
    hashobj = hash_algo()
    with open(filename, "rb") as f:
        if first_chunk_only:
            hashobj.update(f.read(1024))
        else:
            for chunk in chunk_reader(f, chunk_size=chunk_size):
                hashobj.update(chunk)
    return hashobj.digest()


# -----------------------
# Duplicate handling utils
# -----------------------

def choose_keep_index(files: List[str], strategy: str, log: logging.Logger = None) -> int:
    """
    Decide which file index to keep (not rename) within a duplicate group.
    Strategies:
        - 'first': keep the first as-is (sorted by path for determinism)
        - 'mtime_oldest': keep the oldest (smallest mtime)
        - 'mtime_newest': keep the newest (largest mtime)
    """
    if strategy == "first":
        # files already sorted by path before this call
        return 0
    # Build list of (mtime, index)
    mtimes = []
    for i, f in enumerate(files):
        try:
            mtimes.append((os.path.getmtime(f), i))
        except Exception as e:
            if log:
                log.warning(f"Could not read mtime for '{f}': {e}")
            mtimes.append((float("inf"), i))  # push to end
    if strategy == "mtime_oldest":
        return min(mtimes, key=lambda t: t[0])[1]
    elif strategy == "mtime_newest":
        return max(mtimes, key=lambda t: t[0])[1]
    else:
        # Fallback
        return 0


def build_prefixed_path(original_path: str, prefix: str) -> str:
    """
    Return a new path with the given prefix added to the basename.
    If a collision occurs, append a counter: PREFIX{n}_basename.
    Avoid double prefixing if basename already startswith prefix.
    """
    directory = os.path.dirname(original_path)
    basename = os.path.basename(original_path)

    if basename.startswith(prefix):
        # Already marked
        return original_path

    candidate = os.path.join(directory, f"{prefix}{basename}")
    if not os.path.exists(candidate):
        return candidate

    # Resolve collisions by adding numbered prefix
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{prefix}{counter}_{basename}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def rename_file_safe(src: str, prefix: str, dry_run: bool, log: logging.Logger) -> Tuple[str, str]:
    """
    Attempt to rename 'src' by prefixing its basename with 'prefix'.
    Returns (action, new_path):
        action ∈ {'renamed', 'already_marked', 'error'}
        new_path: the target path (or empty on error)
    """
    try:
        target = build_prefixed_path(src, prefix)
        if target == src:
            if log:
                log.info(f"Already marked (skipping): {src}")
            return "already_marked", src
        if dry_run:
            if log:
                log.info(f"DRY-RUN: would rename '{src}' -> '{target}'")
            return "renamed", target
        os.rename(src, target)
        if log:
            log.info(f"Renamed '{src}' -> '{target}'")
        return "renamed", target
    except Exception as e:
        if log:
            log.error(f"Failed to rename '{src}': {e}")
        return "error", ""


# -----------------------
# Core functionality
# -----------------------

def check_for_duplicates(paths: List[str],
                         store_dir: str,
                         hash_name: str = "sha1",
                         chunk_size: int = 65536,
                         log: logging.Logger = None,
                         rename_duplicates: bool = False,
                         prefix: str = "_delete",
                         dry_run: bool = False,
                         keep_strategy: str = "first") -> str:
    """
    Scan provided paths for duplicate files and write results to a timestamped CSV in store_dir.
    Optionally rename duplicates by prefixing their filenames.
    Returns the path to the CSV file.

    IMPORTANT:
    - Files are NEVER renamed unless 'rename_duplicates' is True (set via --rename-duplicates).
    - If 'rename_duplicates' is True and 'dry_run' is True, no actual renames happen.
    """
    # Choose hash algorithm
    hash_map = {
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "blake2b": hashlib.blake2b,
    }
    hash_algo = hash_map.get(hash_name.lower(), hashlib.sha1)

    files_by_size: Dict[int, List[str]] = defaultdict(list)
    files_by_small_hash: Dict[Tuple[int, str], List[str]] = defaultdict(list)
    full_hash_to_files: Dict[str, List[str]] = defaultdict(list)

    total_files_scanned = 0
    inaccessible_files = 0

    # Step 1: Walk directories and collect files by size
    if log:
        log.info("Step 1: Scanning directories and grouping files by size...")
    for path in paths:
        if not os.path.isdir(path):
            if log:
                log.warning(f"Path is not a directory, skipping: {path}")
            continue

        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                try:
                    # Dereference symlinks to actual target file
                    full_path = os.path.realpath(full_path)
                    file_size = os.path.getsize(full_path)
                    files_by_size[file_size].append(full_path)
                    total_files_scanned += 1
                except OSError as e:
                    inaccessible_files += 1
                    if log:
                        log.error(f"Could not access file '{full_path}': {e}")

    if log:
        log.info(f"Total files scanned: {total_files_scanned}")
        log.info(f"Inaccessible files: {inaccessible_files}")
        log.info(f"Unique file sizes: {len(files_by_size)}")

    # Step 2: For files with same size, compute small hash of first 1KB
    if log:
        log.info("Step 2: Computing small hashes (first 1024 bytes) for same-size groups...")
    candidate_size_groups = 0
    for file_size, files in files_by_size.items():
        if len(files) < 2:
            continue  # Unique size; skip
        candidate_size_groups += 1
        for filename in files:
            try:
                small_hash = get_hash(filename, first_chunk_only=True, hash_algo=hash_algo)
                small_hash_hex = small_hash.hex()
                files_by_small_hash[(file_size, small_hash_hex)].append(filename)
            except OSError as e:
                if log:
                    log.error(f"Error reading file for small hash '{filename}': {e}")

    if log:
        log.info(f"Candidate same-size groups: {candidate_size_groups}")
    if log:
        log.info(f"Size+small-hash groups: {len(files_by_small_hash)}")

    # Step 3: For files with same small hash, compute full hash
    if log:
        log.info("Step 3: Computing full hashes for candidates...")
    for (file_size, small_hash_hex), files in files_by_small_hash.items():
        if len(files) < 2:
            continue  # Unique small hash; skip

        for filename in files:
            try:
                full_hash = get_hash(filename, first_chunk_only=False, hash_algo=hash_algo, chunk_size=chunk_size)
                full_hash_hex = full_hash.hex()
                full_hash_to_files[full_hash_hex].append(filename)
            except OSError as e:
                if log:
                    log.error(f"Error reading file for full hash '{filename}': {e}")

    # Prepare timestamped CSV output
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_path = os.path.join(store_dir, f"duplicates-{ts}.csv")
    fieldnames = [
        "duplicate_group_id",
        "group_count",        # 1..N within the group (row index)
        "group_size",         # total N for the group (constant per group)
        "filename",
        "absolute_path",
        "file_size",
        "small_hash_hex",
        "full_hash_hex",
        "detection_method",
        "action",
        "new_absolute_path",
    ]

    if log:
        log.info(f"Step 4: Writing duplicate results to CSV: {csv_path}")

    duplicate_groups = 0
    duplicate_files_total = 0
    renamed_total = 0

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        group_id = 0
        # Sort files per hash group for determinism
        for full_hash_hex, files in full_hash_to_files.items():
            files = sorted(files)
            if len(files) < 2:
                continue  # Not a duplicate group

            group_id += 1
            duplicate_groups += 1
            group_size = len(files)
            duplicate_files_total += group_size

            # Decide which file to keep (not renamed)
            keep_idx = choose_keep_index(files, keep_strategy, log=log)
            keep_path = files[keep_idx]
            if log:
                log.info(
                    f"Group {group_id}: keeping '{keep_path}' (strategy={keep_strategy}); "
                    f"{'planning to ' if rename_duplicates else 'NOT '}rename {group_size - 1} duplicates "
                    f"with prefix '{prefix}' "
                    f"{'(dry-run)' if (rename_duplicates and dry_run) else ''}"
                )

            # Write rows and perform renames only if --rename-duplicates
            for member_index, filename in enumerate(files, start=1):  # 1..N
                abs_path = os.path.realpath(filename)
                try:
                    file_size = os.path.getsize(abs_path)
                    small_hash_hex = get_hash(abs_path, first_chunk_only=True, hash_algo=hash_algo).hex()
                except Exception as e:
                    small_hash_hex = ""
                    file_size = ""
                    if log:
                        log.error(f"Error preparing CSV row for '{filename}': {e}")

                if (member_index - 1) == keep_idx:
                    action = "keep"
                    new_path = abs_path
                else:
                    if rename_duplicates:
                        action, new_path = rename_file_safe(abs_path, prefix, dry_run, log)
                        if action == "renamed" and not dry_run:
                            renamed_total += 1
                    else:
                        # Explicit: do NOT rename unless flag is set
                        action = "duplicate"
                        new_path = abs_path  # unchanged

                writer.writerow({
                    "duplicate_group_id": group_id,
                    "group_count": member_index,   # 1..N inside this group
                    "group_size": group_size,      # constant N for this group
                    "filename": os.path.basename(abs_path),
                    "absolute_path": abs_path,
                    "file_size": file_size,
                    "small_hash_hex": small_hash_hex,
                    "full_hash_hex": full_hash_hex,
                    "detection_method": "size+first1KB+fullhash",
                    "action": action,
                    "new_absolute_path": new_path,
                })

    if log:
        log.info(f"Duplicate groups found: {duplicate_groups}")
        log.info(f"Total duplicate files (rows) written: {duplicate_files_total}")
        if rename_duplicates:
            log.info(f"Duplicates {'planned' if dry_run else 'actually'} renamed: {renamed_total}")
        else:
            log.info("No renaming performed (run with --rename-duplicates to rename).")
        log.info(f"CSV output: {csv_path}")

    return csv_path


# -----------------------
# CLI
# -----------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find duplicate files and export results to CSV, with logging and optional renaming."
    )
    parser.add_argument("paths", nargs="+", help="Folders to scan for duplicates")
    parser.add_argument("--store-dir", default="store", help="Directory to store CSV and log (default: ./store)")
    parser.add_argument("--hash", dest="hash_name", choices=["sha1", "sha256", "blake2b"], default="sha1",
                        help="Hash algorithm to use (default: sha1)")
    parser.add_argument("--chunk-size", type=int, default=65536,
                        help="Chunk size in bytes for full hashing (default: 65536)")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
                        help="Logging verbosity (default: INFO)")

    # Renaming options (disabled unless --rename-duplicates is set)
    parser.add_argument("--rename-duplicates", action="store_true",
                        help="Rename duplicates by prefixing their filenames (keep one per group).")
    parser.add_argument("--prefix", default="_delete",
                        help="Prefix to add to duplicate filenames (default: _delete)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Do not rename; only log and write planned actions to CSV.")
    parser.add_argument("--keep-strategy", choices=["first", "mtime_oldest", "mtime_newest"], default="first",
                        help="Which file in a duplicate group to keep unchanged (default: first).")

    return parser.parse_args()


def main():
    args = parse_args()
    setup_store_dir(args.store_dir)
    logger = setup_logging(args.store_dir, level=args.log_level)

    logger.info("Starting duplicate scan...")
    logger.info(f"Paths: {args.paths}")
    logger.info(f"Store dir: {args.store_dir}")
    logger.info(f"Hash algorithm: {args.hash_name}")
    logger.info(f"Chunk size: {args.chunk_size} bytes")
    logger.info(f"Rename duplicates: {args.rename_duplicates}")
    if args.rename_duplicates:
        logger.info(f"Prefix: {args.prefix} | Dry-run: {args.dry_run} | Keep strategy: {args.keep_strategy}")
    else:
        logger.info("Renaming is DISABLED. To rename duplicates, add --rename-duplicates.")

    try:
        csv_path = check_for_duplicates(
            paths=args.paths,
            store_dir=args.store_dir,
            hash_name=args.hash_name,
            chunk_size=args.chunk_size,
            log=logger,
            rename_duplicates=args.rename_duplicates,  # <-- only renames if True
            prefix=args.prefix,
            dry_run=args.dry_run,
            keep_strategy=args.keep_strategy,
        )
        logger.info("Duplicate scan completed successfully.")
        logger.info(f"Results saved to: {csv_path}")
    except Exception as e:
        logger.error(f"Fatal error during duplicate scan: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Detect first-party artifacts in the local Maven repository that no longer match
their own checksums.

Maven verifies a checksum when it downloads an artifact and never again. An
``mvn install`` writes over whatever is already cached at that coordinate and does
not touch the ``.sha1`` sidecar, so a feature branch built while the tree still
carries the last released version silently replaces that release. The jar and its
sidecar then disagree for as long as the cache survives, and ``mvn -C`` does not
notice: strict checksums apply to transport, not to what is already on disk.

That is not hypothetical. It happened on 2026-09-24 and surfaced two repositories
away, as a compile error in a consumer pinned to nap-spring 0.8.0 whose call site
no longer matched the record it was compiling against. The published artifact was
correct throughout. Only the local copy was wrong, and nothing reported it.

This script is the missing check. It is deliberately not a Maven plugin: the point
is to inspect the repository from outside the build that corrupts it.

Usage:
    python3 check-m2-integrity.py             # check xyz.tcheeric
    python3 check-m2-integrity.py --fix       # also delete the bad coordinates
    python3 check-m2-integrity.py --group-path com/example
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import sys

DEFAULT_GROUP_PATH = "xyz/tcheeric"


def sha1_of(path: pathlib.Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as handle:
        # Chunked so a large jar does not have to be held in memory at once.
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=pathlib.Path,
        default=pathlib.Path.home() / ".m2" / "repository",
        help="Local Maven repository (default: ~/.m2/repository)",
    )
    parser.add_argument(
        "--group-path",
        default=DEFAULT_GROUP_PATH,
        help=f"Group directory to check, slash separated (default: {DEFAULT_GROUP_PATH})",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Delete the version directory of every mismatch so Maven refetches it",
    )
    args = parser.parse_args()

    root = args.repo / args.group_path
    if not root.is_dir():
        # Nothing cached for this group is a perfectly ordinary state, including on a
        # fresh CI runner, so it is not a failure.
        print(f"No artifacts cached under {root}, nothing to check.")
        return 0

    checked = 0
    mismatches: list[tuple[pathlib.Path, str, str]] = []
    unverifiable: list[pathlib.Path] = []

    for jar in sorted(root.rglob("*.jar")):
        sidecar = jar.with_suffix(jar.suffix + ".sha1")
        if not sidecar.is_file():
            # An artifact installed locally and never downloaded has no sidecar to
            # compare against. That is the normal state for a SNAPSHOT or for the
            # version currently being developed, so it is reported rather than failed.
            unverifiable.append(jar)
            continue

        checked += 1
        expected = sidecar.read_text().split()[0].strip() if sidecar.read_text().strip() else ""
        actual = sha1_of(jar)
        if expected != actual:
            mismatches.append((jar, expected, actual))

    print(f"Checked {checked} artifact(s) with checksums under {root}.")
    if unverifiable:
        # Counted, not listed. A developer's cache holds thousands of locally installed
        # jars across unrelated projects, and printing them all buries the one line that
        # matters. The count is still worth showing: it is the size of the blind spot.
        print(
            f"{len(unverifiable)} locally installed artifact(s) have no .sha1 and "
            "cannot be checked."
        )

    if not mismatches:
        print("No checksum mismatches.")
        return 0

    print()
    print(f"{len(mismatches)} artifact(s) do not match their own checksum:")
    for jar, expected, actual in mismatches:
        print(f"  {jar.relative_to(args.repo)}")
        print(f"    .sha1 says : {expected or '(empty)'}")
        print(f"    jar hashes : {actual}")

    if args.fix:
        print()
        for jar, _, _ in mismatches:
            version_dir = jar.parent
            print(f"Removing {version_dir.relative_to(args.repo)}")
            shutil.rmtree(version_dir)
        print("Removed. Maven will refetch these from the repository on the next build.")
        return 0

    print()
    print("A released coordinate was most likely overwritten by a local build of a")
    print("branch whose pom still carried that version. The published artifacts are")
    print("probably fine; it is the cache that is wrong. Re-run with --fix to delete")
    print("these so Maven refetches them.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

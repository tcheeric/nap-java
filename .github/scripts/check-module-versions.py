#!/usr/bin/env python3
"""Fail unless every module in the reactor is at the root pom's version.

A root-only version bump publishes some coordinates at the new version and
leaves the rest behind, so a consumer resolves the parent and then fails on a
module. It is the quieter half of the release problem: the build is green, the
tag exists, and only a consumer finds out.

Sibling of the same check in imani-wallet-lib, where exactly this happened at
0.1.40 (398ja/imani-wallet-lib#51).

This runs on pull requests as well as before publish, so the mismatch is caught
when the bump is proposed rather than after a tag is cut and cannot be moved.

Every module here inherits its version from <parent> rather than declaring its
own, which is the layout that makes a single-command bump possible at all:

    mvn versions:set -DnewVersion=X.Y.Z -DprocessAllModules=true

A module that declares its own <version> is therefore a finding in itself, not
just a mismatch, because it can drift silently from the parent afterwards.
"""
import os
import sys
import xml.etree.ElementTree as ET

NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def poms(pom="pom.xml"):
    """Every pom in the reactor, root first, depth-first."""
    root = ET.parse(pom).getroot()
    here = os.path.dirname(pom)
    yield pom, root
    for module in root.findall("m:modules/m:module", NS):
        yield from poms(os.path.join(here, module.text, "pom.xml"))


def main():
    entries = list(poms())
    root_pom, root = entries[0]
    expected = root.findtext("m:version", namespaces=NS)
    if not expected:
        print(f"::error::{root_pom} declares no <version>")
        return 1

    print(f"root version is {expected}; checking {len(entries) - 1} modules")

    problems = []
    for pom, tree in entries[1:]:
        own = tree.findtext("m:version", namespaces=NS)
        parent = tree.findtext("m:parent/m:version", namespaces=NS)

        # A module must inherit. Declaring its own version is how a partial bump
        # becomes possible, even when the value currently happens to agree.
        if own is not None:
            problems.append(
                f"{pom} declares its own <version>{own}</version>; remove it and "
                f"inherit from <parent>, or a future bump will miss this module"
            )
        if parent != expected:
            problems.append(
                f"{pom} has <parent><version>{parent}</version>, but the root pom "
                f"is {expected} -- this is the 0.1.40 failure exactly"
            )

    for problem in problems:
        print(f"::error::{problem}")

    if problems:
        print(f"::error::{len(problems)} version inconsistencies; the release would be partial")
        return 1

    print(f"all {len(entries) - 1} modules inherit {expected}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Fail unless every reactor module resolves in the registry at VERSION.

A green tag push must imply the artifacts shipped. In this repository nothing
shipped for 0.9.0: the pom said 0.9.0 while the newest tag was v0.8.0 and there
was no release workflow at all, so nap-spring and nap-jdbc 0.9.0 were never
published.

The damage landed on consumers rather than here. Every imani-bom from 0.1.106
onward pins nap-java 0.9.0, so cashu-mint's CI could not resolve nap-spring at
all while building fine on a developer machine from a locally installed ~/.m2
copy. This repository's own CI stayed green throughout, because nothing it runs
depends on the artifacts existing anywhere but locally.

Two distinct failures have to be caught, and only an after-the-fact resolve
check catches both:

  * nothing published -- no workflow, or credentials absent, or the upload
    rejected. The build is green either way.
  * partially published -- a root-only version bump leaves submodules behind,
    so some coordinates exist at the new version and others do not.

Ported from cashu-vault, which lost publishing the same way and fixed it the
same way. Reading <modules> depends on nothing outside the checkout.
"""
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
BASE = "https://maven.398ja.xyz/releases/xyz/tcheeric"


def reactor_artifacts(pom="pom.xml"):
    """Every artifactId the reactor builds, root first, depth-first."""
    root = ET.parse(pom).getroot()
    here = os.path.dirname(pom)
    yield root.findtext("m:artifactId", namespaces=NS)
    for module in root.findall("m:modules/m:module", NS):
        yield from reactor_artifacts(os.path.join(here, module.text, "pom.xml"))


def resolves(url):
    request = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except OSError as error:
        return f"unreachable ({error})"


def main():
    version = os.environ.get("VERSION", "").lstrip("v")
    if not version:
        print("::error::VERSION is empty; refusing to report success")
        return 1

    artifacts = list(reactor_artifacts())
    if not artifacts:
        print("::error::no reactor modules found; refusing to report success")
        return 1

    print(f"verifying {len(artifacts)} reactor modules at {version}")
    failed = 0
    for artifact in artifacts:
        url = f"{BASE}/{artifact}/{version}/{artifact}-{version}.pom"
        status = resolves(url)
        if status == 200:
            print(f"  ok    {artifact}")
        else:
            print(f"::error::{artifact} {version} not published (HTTP {status}) {url}")
            failed += 1

    if failed:
        print(f"::error::{failed} of {len(artifacts)} modules did not publish")
        return 1
    print(f"all {len(artifacts)} modules resolve at {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

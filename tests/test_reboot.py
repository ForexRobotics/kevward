# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Forex Robotics Co., Ltd.

"""Unit tests for pkg_needs_reboot — only the kernel image and glibc warrant a
reboot flag; firmware/headers/tools and libc*-prefixed libraries must not."""

from __future__ import annotations

from kevward.util import pkg_needs_reboot


def test_kernel_image_needs_reboot():
    assert pkg_needs_reboot("linux-image-6.8.0-149-generic")
    assert pkg_needs_reboot("linux-image-generic")


def test_glibc_needs_reboot():
    assert pkg_needs_reboot("libc6")
    assert pkg_needs_reboot("libc6-dev")


def test_linux_prefixed_non_kernel_do_not_reboot():
    # the regression: these all start with "linux-" but need no reboot
    for p in ("linux-firmware-amd-graphics", "linux-firmware",
              "linux-headers-6.8.0-149-generic", "linux-tools-common",
              "linux-libc-dev", "linux-cloud-tools-common"):
        assert not pkg_needs_reboot(p), p


def test_libc_prefixed_libraries_do_not_reboot():
    for p in ("libcurl4", "libcups2", "libcairo2", "libclang1",
              "libc-ares2", "libcrypt1"):
        assert not pkg_needs_reboot(p), p


def test_ordinary_packages_do_not_reboot():
    for p in ("apt", "apt-utils", "libapt-pkg6.0", "python3-twisted",
              "libsqlite3-0"):
        assert not pkg_needs_reboot(p), p


if __name__ == "__main__":
    for name, obj in sorted(globals().items()):
        if name.startswith("test_") and callable(obj):
            obj()
            print(f"ok  {name}")
    print("all reboot tests passed")

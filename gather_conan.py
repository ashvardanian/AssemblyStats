#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Uses the undocumented Conans Python interface to collect binaries from artifactory.
    https://github.com/conan-io/conan/issues/6315#issuecomment-572679136
    https://github.com/conan-io/docs/issues/44#issuecomment-510467609
    https://www.jfrog.com/confluence/display/BT/Conan+Repositories
    https://conan.io/center/
"""
import conans
from conans.client.conan_api import Conan
from conans.model.ref import ConanFileReference

if __name__ == '__main__':
    # Specify the packages with following convention:
    # "my-pkg/0.0.1@my-usr/release",
    # You can search for full name via:
    # conan search protobuf -r=conan-center
    # "libcurl/7.75.0@",
    pkgs = ["zlib/1.2.11@conan/stable"]
    for pkg in pkgs:
        ref = ConanFileReference.loads(pkg, validate=False)
        # ref.user_io = {'out': None}
        Conan.install_reference(
            ref,
            install_folder='tmp',
            # generators=['deploy'],
        )

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import conda
from conda.api import *

if __name__ == '__main__':
    channels = Channel('conda-forge')
    solver = Solver('zlib', channels=channels)

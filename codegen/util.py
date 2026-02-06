"""Utility functions for codegen."""

import re

import capstone
import keystone
import unicorn

# Libraries that use a <int> type const as a fake enum
INT_CONSTS_LIBS = [capstone, keystone, unicorn]


def getattr_regex(obj, pattern):
    return {name: getattr(obj, name) for name in dir(obj) if re.match(pattern, name)}


def non_dunder_members(obj):
    return {
        name: getattr(obj, name)
        for name in dir(obj)
        if not name.startswith("__") and not name.endswith("__")
    }

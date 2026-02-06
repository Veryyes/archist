"""Utility functions for codegen."""

import re
import typing

import capstone
import keystone
import unicorn

# Libraries that use a <int> type const as a fake enum
INT_CONSTS_LIBS = [capstone, keystone, unicorn]


def getattr_regex(obj, pattern, group_no: int = 0):
    var_map: typing.Dict[str, int] = dict()
    for name in dir(obj):
        m = re.match(pattern, name)
        if m is None:
            continue

        var_map[m.group(group_no)] = getattr(obj, name)
    return var_map


def non_dunder_members(obj):
    return {
        name: getattr(obj, name)
        for name in dir(obj)
        if not name.startswith("__") and not name.endswith("__")
    }

#reference: https://medium.com/assertqualityassurance/tutorial-de-pytest-para-iniciantes-cbdd81c6d761
import codecs
import os
import shutil
import struct
from pprint import pprint
import pytest, sys

from frida_fusion.libs.color import Color
from frida_fusion.module import Module, ModuleManager


def test_01_modules():
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    try:
        mods = ModuleManager.list_modules()

        if len(mods) == 0:
            raise Exception("no modules found")

        assert True
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        assert False


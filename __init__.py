import binaryninja
from binaryninja import CallingConvention
from binaryninja.architecture import Architecture

from .s1c88 import S1C88
S1C88.register()

from .view import S1C88View
S1C88View.register()

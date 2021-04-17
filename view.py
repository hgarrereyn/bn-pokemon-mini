from struct import unpack

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.types import Symbol

from .mmaps import mmio_regs, default_symbols

class S1C88View(BinaryView):
    name = "PokeROM"
    long_name = "Pokemon Mini ROM"

    @classmethod
    def is_valid_for_data(self, data: BinaryView):
        print(type(data))

        header = data.read(0x21A4,24)
        return header == b"NINTENDOMPKMminipokemon\x00"

    def __init__(self, data: BinaryView):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['s1c88:s1c88'].standalone_platform
        self.data = data


    def init(self):
        # RAM
        self.add_auto_segment(0x1000, 0x1000, 0, 0x1000, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        # Hardware IO Registers
        self.add_auto_segment(0x2000, 0x100, 0, 0x100, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        # Cartridge memory
        self.add_auto_segment(0x2100, 0x1fdeff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

        # Cartridge memory mirrors
        self.add_auto_segment(0x200000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x400000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x600000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x800000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xA00000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xC00000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xE00000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

        for addr, name in default_symbols.items():
            self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
        
        for addr, name in mmio_regs.items():
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, addr, name))



        self.add_entry_point(0x2102)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x2102

from struct import unpack

from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag, SymbolType
from binaryninja.types import Symbol



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
        self.add_auto_segment(0x2100, 0x1fdeff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x200000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x400000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x600000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0x800000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xA00000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xC00000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)
        self.add_auto_segment(0xE00000, 0x1fffff, 0x2100, 0x1fdeff, SegmentFlag.SegmentReadable|SegmentFlag.SegmentExecutable)

        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002102, "reset_vector"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002108, "prc_frame_copy_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00210E, "prc_render_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002114, "timer_2h_underflow_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00211A, "timer_2l_underflow_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002120, "timer_1h_underflow_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002126, "timer_1l_underflow_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00212C, "timer_3h_underflow_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002132, "timer_3_cmp_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002138, "timer_32hz_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00213E, "timer_8hz_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002144, "timer_2hz_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00214A, "timer_1hz_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002150, "ir_rx_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002156, "shake_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00215C, "key_power_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002162, "key_right_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002168, "key_left_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00216E, "key_down_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002174, "key_up_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00217A, "key_c_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002180, "key_b_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002186, "key_a_irq"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00218C, "unknown_irq0"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002192, "unknown_irq1"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x002198, "unknown_irq2"))
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0x00219E, "cartridge_irq"))


        self.add_entry_point(0x2102)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0x2102

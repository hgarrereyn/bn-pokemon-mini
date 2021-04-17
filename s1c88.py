from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .instr import decode, tT



class S1C88(Architecture):
    name = 's1c88:s1c88'
    address_size = 2
    max_instr_length = 8

    regs = {
        'BA': RegisterInfo('BA', 2),
		'A': RegisterInfo('BA', 1, 0),
        'B': RegisterInfo('BA', 1, 1),
        'HL': RegisterInfo('HL', 2),
		'L': RegisterInfo('HL', 1, 0),
        'H': RegisterInfo('HL', 1, 1),
        'IX': RegisterInfo('IX', 2),
        'IY': RegisterInfo('IY', 2),
        'PC': RegisterInfo('PC', 2),
        'SP': RegisterInfo('SP', 2),
        'BR': RegisterInfo('BR', 1),
        'NB': RegisterInfo('NB', 1),
        'CB': RegisterInfo('CB', 1),
        'EP': RegisterInfo('EP', 1),
        'IP': RegisterInfo('YP', 2),
        'XP': RegisterInfo('XP', 1, 0),
        'YP': RegisterInfo('YP', 1, 1),
        'SC': RegisterInfo('SC', 1),
    }
    stack_pointer = 'SP'

    flags = ['c', 'nc', 'z', 'nz', 'lt', 'le', 'gt', 'ge', 'v', 'nv', 'p', 'm']

    def get_instruction_info(self, data, addr):

        r = decode(data, addr)

        if r is None:
            return None

        return r[1]

    def get_instruction_text(self, data, addr):

        r = decode(data, addr)

        if r is None:
            return None

        return r[0], r[1].length

    def get_instruction_low_level_il(self, data, addr, il):

        r = decode(data, addr)

        if r is None:
            return None

        fn = r[2]
        if fn is not None:
            for f in fn:
                f(il)

        return r[1].length

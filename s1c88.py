from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, FlagRole, LowLevelILFlagCondition

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

    flags = ['z', 'c', 'v', 'n', 'd', 'u', 'i0', 'i1',]

    flag_roles = {
        'z': FlagRole.ZeroFlagRole,
        'c': FlagRole.CarryFlagRole,
        'v': FlagRole.OverflowFlagRole,
        'n': FlagRole.NegativeSignFlagRole,
        'd': FlagRole.SpecialFlagRole,
        'u': FlagRole.SpecialFlagRole,
        'i0': FlagRole.SpecialFlagRole,
        'i1': FlagRole.SpecialFlagRole,
    }

    flags_required_for_flag_condition = {
        # Unsigned comparisons
        LowLevelILFlagCondition.LLFC_UGE: ['c'],
        LowLevelILFlagCondition.LLFC_ULT: ['c'],
        # Signed comparisions
        LowLevelILFlagCondition.LLFC_SGE: ['n', 'v'],
        LowLevelILFlagCondition.LLFC_SGT: ['z', 'n', 'v'],
        LowLevelILFlagCondition.LLFC_SLE: ['z', 'n', 'v'],
        LowLevelILFlagCondition.LLFC_SLT: ['n', 'v'],
        # Equals or not
        LowLevelILFlagCondition.LLFC_E: ['z'],
        LowLevelILFlagCondition.LLFC_NE: ['z'],
        # Overflow or not
        LowLevelILFlagCondition.LLFC_NO: ['v'],
        LowLevelILFlagCondition.LLFC_O: ['v'],
        # Negative or not
        LowLevelILFlagCondition.LLFC_NEG: ['n'],
        LowLevelILFlagCondition.LLFC_POS: ['n']
    }

    flag_write_types = [
        ''
        "*",
        "zcvn",
        "zn",
        "z",
        "zcn",
    ]

    flags_written_by_flag_write_type = {
		"*": ['z', 'c', 'v', 'n', 'd', 'u', 'i0', 'i1'],
        "zcvn": ["z", "c", "v", "n"],
        "zn": ["z", "n"],
        "z": ["z"],
        "zcn": ["z", "c", "n"],
	}

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


from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, LowLevelILOperation
from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel

from .minidis2_instr import instructions

# binary ninja text helpers
def tI(x): return InstructionTextToken(InstructionTextTokenType.InstructionToken, x)
def tR(x): return InstructionTextToken(InstructionTextTokenType.RegisterToken, x)
def tS(x): return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)
def tM(x): return InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)
def tE(x): return InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)
def tA(x,d): return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)
def tT(x): return InstructionTextToken(InstructionTextTokenType.TextToken, x)
def tN(x,d): return InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)


def u32(dat):
    x = 0
    x += dat[0]
    x += (dat[1] << 8)
    x += (dat[2] << 16)
    x += (dat[3] << 24)
    return x

def u16(dat):
    x = 0
    x += dat[0]
    x += (dat[1] << 8)
    return x

def bits(x,hi,lo):
    '''bits hi to lo inclusive'''
    return (x >> lo) & ((2 ** (hi - lo + 1)) - 1)

def ext(x,n):
    '''sign extend x as an "n" bit number'''
    if (x >> (n-1)) & 1:
        # invert
        return -((2**n) - x)
    else:
        return x

# LLIL branching util

def il_jump(il, dest, is_call=False):

    if is_call:
        il.append(il.call(dest))
    else:
        # lookup label 
        t = None
        if il[dest].operation == LowLevelILOperation.LLIL_CONST:
            t = il.get_label_for_address(Architecture['s1c88:s1c88'], il[dest].constant)

        # if the label doesn't exist, create a new one
        indirect = False
        if t is None:
            t = LowLevelILLabel()
            indirect = True

        # if it doesn't exist, create and jump
        if indirect:
            il.mark_label(t)
            il.append(il.jump(dest))
        else:
            # just goto label
            il.append(il.goto(t))


def il_branch(il, cond, tdest, fdest):
    
    # lookup the true branch
    t_target = None
    if il[tdest].operation == LowLevelILOperation.LLIL_CONST:
        t_target = il.get_label_for_address(Architecture['s1c88:s1c88'], il[tdest].constant)

    # if the label doesn't exist, create a new one
    indirect = False
    if t_target is None:
        t_target = LowLevelILLabel()
        indirect = True

    # create the false branch
    f_target = LowLevelILLabel()

    # create the if_expr
    il.append(il.if_expr(cond, t_target, f_target))

    # handle true target if indirect
    if indirect:
        il.mark_label(t_target)
        il.append(il.jump(tdest))

    # mark false branch
    il.mark_label(f_target)


def cat2(il, a, b):
    return il.add(
        2,
        il.shift_left(2, il.zero_extend(2, a), il.const(1, 8)),
        b
    )


def set_op(op, immdata, addr):
    # returns (text, il)
    if op in ['A','B','H','L','BR','NB','CB','EP','XP','YP','SC']:
        return ([tR(op)], lambda il,v: il.set_reg(1, op, v))
    elif op in ['AB','HL','IX','IY','SP']:
        return ([tR(op)], lambda il,v: il.set_reg(2, op, v))
    elif op == '[BR:{0}h]':
        r = immdata[0]
        fn = lambda il,v: il.store(1, cat2(il, il.reg(1, 'BR'), il.const(1, r)), v)
        return ([
            tM('['), tR('BR'), tS(':'), tN(hex(r), r), tE(']')
        ], fn)
    else:
        return ([tT(op)], None)

def load_op(op, immdata, addr):
    # returns (text, il)
    if op in ['A','B','H','L','BR','NB','CB','EP','XP','YP','SC']:
        return ([tR(op)], lambda il: il.reg(1, op))
    elif op in ['AB','HL','IX','IY','SP']:
        return ([tR(op)], lambda il: il.reg(2, op))
    elif op == '#{0}h':
        # uint8_t
        v = immdata[0]
        return ([tN(hex(v), v)], lambda il: il.const(1,v))
    elif op == '#{1}h':
        # uint16_t
        v = immdata[0] + (immdata[1] << 8)
        return ([tN(hex(v), v)], lambda il: il.const(2,v))
    elif op == '#{4}h':
        # second uint8_t
        v = immdata[1]
        return ([tN(hex(v), v)], lambda il: il.const(1,v))
    else:
        return ([tT(op)], lambda il: il.const(1,0))


def load(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    info = InstructionInfo()
    info.length = length

    dst, src = txt.split()[1].split(',')

    p_dst = set_op(dst, immdata, addr)
    p_src = load_op(src, immdata, addr)

    fn = None
    if p_dst[1] is not None and p_src[1] is not None:
        fn = [lambda il: il.append(p_dst[1](il, p_src[1](il)))]

    return (
        [tT('LD'), tS(' '), *p_dst[0], tS(', '), *p_src[0]],
        info,
        fn
    )

def jrl(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    if txt.split()[1] != '{3}':
        return None

    rel = immdata[0] + (immdata[1] << 8)
    target = (addr + rel + length - 1) & 0xffff

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.UnconditionalBranch, target)

    return (
        [tT('JRL'), tS(' '), tA(hex(target), target)],
        info,
        [lambda il: il.append(il.jump(il.const_pointer(2, target)))]
    )

def carl(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    if txt.split()[1] != '{3}':
        return None

    rel = immdata[0] + (immdata[1] << 8)
    target = (addr + rel + length - 1) & 0xffff

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.CallDestination, target)

    return (
        [tT('CARL'), tS(' '), tA(hex(target), target)],
        info,
        [lambda il: il_jump(il, il.const_pointer(2, target), is_call=True)]
    )

def rete(instr, dat, addr):
    txt, code, length = instr

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.FunctionReturn)

    return (
        [tT('RETE')],
        info,
        [lambda il: il.append(il.unimplemented())]
    )

def decode(dat, addr):
    
    if len(dat) < 1:
        return None

    b0 = dat[0]
    instr = instructions[b0]

    if instr is not None and len(instr) != 3:
        # multi-byte encoding
        if len(dat) < 2:
            return None

        b1 = dat[1]
        instr = instr[b1]

    if instr is None or len(dat) < instr[2]:
        return None

    txt, code, length = instr

    info = InstructionInfo()
    info.length = length

    op = txt.split()[0]

    if op == 'LD': return load(instr, dat, addr)
    elif op == 'JRL': return jrl(instr, dat, addr)
    elif op == 'CARL': return carl(instr, dat, addr)
    elif op == 'RETE': return rete(instr, dat, addr)

    return ([tT(txt)], info, None)


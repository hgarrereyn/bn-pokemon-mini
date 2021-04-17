
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

REGS_1 = ['A','B','H','L','BR','NB','CB','EP','XP','YP','SC']
REGS_2 = ['BA','HL','IX','IY','SP','IP']

# LLIL branching util

def s8(v):
    if v & 0x80:
        v -= 0x100
    return v

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
    if op in REGS_1:
        return ([tR(op)], lambda il,v: il.set_reg(1, op, v))
    elif op in REGS_2:
        return ([tR(op)], lambda il,v: il.set_reg(2, op, v))
    elif op == '[BR:{0}h]':
        r = immdata[0]
        fn = lambda il,v: il.store(1, cat2(il, il.reg(1, 'BR'), il.const(1, r)), v)
        return ([
            tM('['), tR('BR'), tS(':'), tN(hex(r), r), tE(']')
        ], fn)
    elif op == '[{1}h]':
        r = immdata[0] + (immdata[1] << 8)
        fn = lambda il,v: il.store(1, il.const(2, r), v)
        return ([
            tM('['), tN(hex(r), r), tE(']')
        ], fn)
    elif op == '[HL]':
        return ([
            tM('['), tR('HL'), tE(']')
        ], lambda il, v: il.store(1, il.reg(2, 'HL'), v))
    elif op == '[IX]':
        return ([
            tM('['), tR('IX'), tE(']')
        ], lambda il, v: il.store(1, il.reg(2, 'IX'), v))
    elif op == '[IY]':
        return ([
            tM('['), tR('IY'), tE(']')
        ], lambda il, v: il.store(1, il.reg(2, 'IY'), v))
    elif op == '[SP+{0}h]':
        v = immdata[0]
        return ([
            tM('['), tR('SP'), tS('+'), tN(hex(v), v), tE(']'),
        ], lambda il, vv: il.store(1, 
            il.add(2,
                il.reg(2, 'SP'),
                il.const(2, v)
            ),
            vv
        ), 1)
    elif op == '[IX+{2}h]':
        v = s8(immdata[0])
        return ([
            tM('['), tR('IX'), tS('+') if v > 0 else tS('-'), tN(hex(abs(v)), abs(v)), tE(']'),
        ], lambda il, vv: il.store(1, 
            il.add(2,
                il.reg(2, 'IX'),
                il.const(2, v)
            ),
            vv
        ), 1)
    elif op == '[IY+L]':
        return ([
            tM('['), tR('IX'), tS('+'), tR('L'), tE(']'),
        ], lambda il, vv: il.store(1, 
            il.add(2,
                il.reg(2, 'IY'),
                il.zero_extend(2, il.reg(1, 'L'))
            ),
            vv
        ), 1)
    else:
        return ([tT(op)], None)

def load_op(op, immdata, addr):
    # returns (text, il, size)
    if op in REGS_1:
        return ([tR(op)], lambda il: il.reg(1, op), 1)
    elif op in REGS_2:
        return ([tR(op)], lambda il: il.reg(2, op), 2)
    elif op == '#{0}h':
        # uint8_t
        v = immdata[0]
        return ([tN(hex(v), v)], lambda il: il.const(1,v), 1)
    elif op == '#{1}h':
        # uint16_t
        v = immdata[0] + (immdata[1] << 8)
        return ([tN(hex(v), v)], lambda il: il.const(2,v), 2)
    elif op == '[{1}h]':
        v = immdata[0] + (immdata[1] << 8)
        return ([
            tM('['), tN(hex(v), v), tE(']')
        ], lambda il: il.load(1, il.const(2,v)), 1)
    elif op == '#{4}h':
        # second uint8_t
        v = immdata[1]
        return ([tN(hex(v), v)], lambda il: il.const(1,v), 1)
    elif op == '[IX+{2}h]':
        v = s8(immdata[0])
        return ([
            tM('['), tR('IX'), tS('+') if v > 0 else tS('-'), tN(hex(abs(v)), abs(v)), tE(']'),
        ], lambda il: il.load(1, 
            il.add(2,
                il.reg(2, 'IX'),
                il.const(2, v)
            )
        ), 1)
    elif op == '[IY+{2}h]':
        v = s8(immdata[0])
        return ([
            tM('['), tR('IY'), tS('+') if v > 0 else tS('-'), tN(hex(abs(v)), abs(v)), tE(']'),
        ], lambda il: il.load(1, 
            il.add(2,
                il.reg(2, 'IY'),
                il.const(2, v)
            )
        ), 1)
    elif op == '[SP+{0}h]':
        v = immdata[0]
        return ([
            tM('['), tR('SP'), tS('+'), tN(hex(v), v), tE(']'),
        ], lambda il: il.load(1, 
            il.add(2,
                il.reg(2, 'SP'),
                il.const(2, v)
            )
        ), 1)
    elif op == '[HL]':
        return ([
            tM('['), tR('HL'), tE(']')
        ], lambda il: il.load(1, il.reg(2, 'HL')), 1)
    elif op == '[IX]':
        return ([
            tM('['), tR('IX'), tE(']')
        ], lambda il: il.load(1, il.reg(2, 'IX')), 1)
    elif op == '[IY]':
        return ([
            tM('['), tR('IY'), tE(']')
        ], lambda il: il.load(1, il.reg(2, 'IY')), 1)
    else:
        return ([tT(op)], lambda il: il.const(1,0), 1)


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

def cp(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    info = InstructionInfo()
    info.length = length

    dst, src = txt.split()[1].split(',')

    p_dst_r = load_op(dst, immdata, addr)
    p_src_r = load_op(src, immdata, addr)

    fn = None
    if p_dst_r[1] is not None and p_src_r[1] is not None:
        fn = [lambda il: il.append(il.compare_equal(p_dst_r[2], 
            p_dst_r[1](il),
            p_src_r[1](il)
        ))]

    return (
        [tT('CP'), tS(' '), *p_dst_r[0], tS(', '), *p_src_r[0]],
        info,
        fn
    )

def binop(op, il_op):
    def _fn(instr, dat, addr):
        txt, code, length = instr
        immdata = dat[len(code):]

        info = InstructionInfo()
        info.length = length

        dst, src = txt.split()[1].split(',')

        p_dst_w = set_op(dst, immdata, addr)
        p_dst_r = load_op(dst, immdata, addr)
        p_src_r = load_op(src, immdata, addr)

        fn = None
        if p_dst_r[1] is not None and p_src_r[1] is not None and p_dst_w[1] is not None:
            fn = [lambda il: il.append(p_dst_w[1](il, getattr(il, il_op)(p_dst_r[2], 
                p_dst_r[1](il),
                p_src_r[1](il)
            )))]

        return (
            [tT(op), tS(' '), *p_dst_w[0], tS(', '), *p_src_r[0]],
            info,
            fn
        )

    return _fn

add = binop('ADD', 'add')
sub = binop('SUB', 'sub')
f_or = binop('OR', 'or_expr')
f_and = binop('AND', 'and_expr')
f_xor = binop('XOR', 'xor_expr')

def ex(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    info = InstructionInfo()
    info.length = length

    dst, src = txt.split()[1].split(',')

    p_dst_w = set_op(dst, immdata, addr)
    p_dst_r = load_op(dst, immdata, addr)
    p_src_w = set_op(src, immdata, addr)
    p_src_r = load_op(src, immdata, addr)

    fn = None
    if p_dst_r[1] is not None and p_src_r[1] is not None and p_dst_w[1] is not None and p_src_w[1] is not None:
        fn = [
            lambda il: il.append(p_dst_w[1](il, p_src_r[1](il))),
            lambda il: il.append(p_src_w[1](il, p_dst_r[1](il)))
        ]

    return (
        [tT('EX'), tS(' '), *p_dst_w[0], tS(', '), *p_src_r[0]],
        info,
        fn
    )


def inc(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    info = InstructionInfo()
    info.length = length

    dst = txt.split()[1]

    p_dst_w = set_op(dst, immdata, addr)
    p_dst_r = load_op(dst, immdata, addr)

    fn = None
    if p_dst_r[1] is not None and p_dst_w[1] is not None:
        fn = [lambda il: il.append(p_dst_w[1](il, il.add(p_dst_r[2], 
            p_dst_r[1](il),
            il.const(p_dst_r[2], 1)
        )))]

    return (
        [tT('INC'), tS(' '), *p_dst_w[0]],
        info,
        fn
    )

def dec(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    info = InstructionInfo()
    info.length = length

    dst = txt.split()[1]

    p_dst_w = set_op(dst, immdata, addr)
    p_dst_r = load_op(dst, immdata, addr)

    fn = None
    if p_dst_r[1] is not None and p_dst_w[1] is not None:
        fn = [lambda il: il.append(p_dst_w[1](il, il.sub(p_dst_r[2], 
            p_dst_r[1](il),
            il.const(p_dst_r[2], 1)
        )))]

    return (
        [tT('DEC'), tS(' '), *p_dst_w[0]],
        info,
        fn
    )

def jrl(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    ops = txt.split()[1].split(',')

    if len(ops) == 1:
        if ops[0] != '{3}':
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
    else:
        # Conditional
        if ops[1] != '{3}':
            return None

        rel = immdata[0] + (immdata[1] << 8)
        target = (addr + rel + length - 1) & 0xffff

        info = InstructionInfo()
        info.length = length
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, addr + length)

        return (
            [tT('JRL'), tS(' '), tT(ops[0]), tS(', '), tA(hex(target), target)],
            info,
            [lambda il: il_branch(il, il.flag(ops[0].lower()), il.const_pointer(2, target), il.const_pointer(2, addr + length))]
        )

def jrs(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    ops = txt.split()[1].split(',')

    if len(ops) == 1:
        # JRS {2}
        if ops[0] != '{2}':
            return None

        rel = immdata[0]
        if rel & 0x80:
            rel -= 0x100
        
        target = (addr + rel + length - 1) & 0xffff

        info = InstructionInfo()
        info.length = length
        info.add_branch(BranchType.UnconditionalBranch, target)

        return (
            [tT('JRS'), tS(' '), tA(hex(target), target)],
            info,
            [lambda il: il.append(il.jump(il.const_pointer(2, target)))]
        )
    else:
        # Conditional
        if ops[1] != '{2}':
            return None

        rel = immdata[0]
        if rel & 0x80:
            rel -= 0x100
        
        target = (addr + rel + length - 1) & 0xffff

        info = InstructionInfo()
        info.length = length
        info.add_branch(BranchType.TrueBranch, target)
        info.add_branch(BranchType.FalseBranch, addr + length)

        return (
            [tT('JRS'), tS(' '), tT(ops[0]), tS(', '), tA(hex(target), target)],
            info,
            [lambda il: il_branch(il, il.flag(ops[0].lower()), il.const_pointer(2, target), il.const_pointer(2, addr + length))]
        )

def djr(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    rel = immdata[0]
    if rel & 0x80:
        rel -= 0x100
    
    target = (addr + rel + length - 1) & 0xffff

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.TrueBranch, target)
    info.add_branch(BranchType.FalseBranch, addr + length)

    return (
        [tT('DJR'), tS(' '), tA(hex(target), target)],
        info,
        [
            lambda il: il_branch(
                il,
                il.compare_not_equal(1, il.reg(1, 'B'), il.const(1, 0)),
                il.const_pointer(2, target),
                il.const_pointer(2, addr + length))
        ]
    )

def f_int(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    op = txt.split()[1]

    if op != '[{0}h]':
        return None

    rel = immdata[0]
    target = rel & 0xff

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.CallDestination, target)

    return (
        [tT('INT'), tS(' '), tA(hex(target), target)],
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

def ret(instr, dat, addr):
    txt, code, length = instr

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.FunctionReturn)

    return (
        [tT('RET')],
        info,
        [lambda il: il.append(il.ret(il.pop(2)))]
    )

def rete(instr, dat, addr):
    txt, code, length = instr

    info = InstructionInfo()
    info.length = length
    info.add_branch(BranchType.FunctionReturn)

    return (
        [tT('RETE')],
        info,
        [lambda il: il.append(il.ret(il.pop(2)))]
    )

def push(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    op = txt.split()[1]
    p_op = load_op(op, immdata, addr)

    info = InstructionInfo()
    info.length = length

    return (
        [tT('PUSH'), tS(' '), *p_op[0]],
        info,
        [lambda il: il.append(il.push(p_op[2], p_op[1](il)))]
    )

def pop(instr, dat, addr):
    txt, code, length = instr
    immdata = dat[len(code):]

    op = txt.split()[1]

    info = InstructionInfo()
    info.length = length

    sz = 0
    if op in REGS_1:
        sz = 1
    elif op in REGS_2:
        sz = 2
    else:
        return None

    return (
        [tT('POP'), tS(' '), tR(op)],
        info,
        [lambda il: il.append(il.set_reg(sz, op, il.pop(sz)))]
    )

def mlt(instr, dat, addr):
    txt, code, length = instr

    info = InstructionInfo()
    info.length = length

    return (
        [tT('MLT')],
        info,
        [lambda il: il.append(il.set_reg(2, 'HL', il.mult(2,
            il.zero_extend(2, il.reg(1, 'A')),
            il.zero_extend(2, il.reg(1, 'L')),
        )))]
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
    elif op == 'JRS': return jrs(instr, dat, addr)
    elif op == 'CARL': return carl(instr, dat, addr)
    elif op == 'RET': return ret(instr, dat, addr)
    elif op == 'RETE': return rete(instr, dat, addr)
    elif op == 'PUSH': return push(instr, dat, addr)
    elif op == 'POP': return pop(instr, dat, addr)
    elif op == 'MLT': return mlt(instr, dat, addr)
    elif op == 'ADD': return add(instr, dat, addr)
    elif op == 'SUB': return sub(instr, dat, addr)
    elif op == 'AND': return f_and(instr, dat, addr)
    elif op == 'OR': return f_or(instr, dat, addr)
    elif op == 'XOR': return f_xor(instr, dat, addr)
    elif op == 'INC': return inc(instr, dat, addr)
    elif op == 'DEC': return dec(instr, dat, addr)
    elif op == 'CP': return cp(instr, dat, addr)
    elif op == 'EX': return ex(instr, dat, addr)
    elif op == 'INT': return f_int(instr, dat, addr)
    elif op == 'DJR': return djr(instr, dat, addr)

    return ([tT(txt)], info, None)


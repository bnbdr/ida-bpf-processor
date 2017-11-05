from idaapi import *
import copy


def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m

class Code(object):
    def _get_class(self, code):
        #define BPF_CLASS(code) ((code) & 0x07)
        return (code) & 0x07

    def _get_size(self, code):
        #define BPF_SIZE(code)	((code) & 0x18)
        return (code) & 0x18

    def _get_mode(self, code):
        #define BPF_MODE(code)	((code) & 0xe0)
        return (code) & 0xe0
    def _get_op(self, code):
        #define BPF_OP(code)	((code) & 0xf0)
        return (code) & 0xf0

    def _get_src(self, code):
        #define BPF_SRC(code)	((code) & 0x08)
        return (code) & 0x08

    def _get_rval(self, code):
        #define BPF_RVAL(code)	((code) & 0x18)
        return (code) & 0x18

    def _get_miscop(self, code):
        #define BPF_MISCOP(code) ((code) & 0xf8)
        return (code) & 0xf8

    def __init__(self, code):
        self._class = self._get_class(code)
        self._size = self._get_size(code)
        self._mode = self._get_mode(code)
        self._op = self._get_op(code)
        self._src = self._get_src(code)
        self._rval = self._get_rval(code)
        self._miscop = self._get_miscop(code)


BPF_INST_SIZE = 8

class BPF_CLASS:        
    BPF_LD		= 0x00
    BPF_LDX		= 0x01
    BPF_ST		= 0x02
    BPF_STX		= 0x03
    BPF_ALU		= 0x04
    BPF_JMP		= 0x05
    BPF_RET		= 0x06
    BPF_MISC	= 0x07

class BPF_SIZE:
    BPF_W		= 0x00
    BPF_H		= 0x08
    BPF_B		= 0x10

class BPF_MODE:
    BPF_IMM 	= 0x00
    BPF_ABS		= 0x20
    BPF_IND		= 0x40
    BPF_MEM		= 0x60
    BPF_LEN		= 0x80
    BPF_MSH		= 0xa0

class BPF_OP:
    BPF_ADD		= 0x00
    BPF_SUB		= 0x10
    BPF_MUL		= 0x20
    BPF_DIV		= 0x30
    BPF_OR		= 0x40
    BPF_AND		= 0x50
    BPF_LSH		= 0x60
    BPF_RSH		= 0x70
    BPF_NEG		= 0x80
    BPF_MOD		= 0x90
    BPF_XOR		= 0xa0

    BPF_JA		= 0x00
    BPF_JEQ		= 0x10
    BPF_JGT		= 0x20
    BPF_JGE		= 0x30
    BPF_JSET	= 0x40

class BPF_SRC:
    BPF_K		= 0x00
    BPF_X		= 0x08

class BPF_RVAL:
    BPF_K		= 0x00
    BPF_X		= 0x08
    BPF_A       = 0x10

class BPF_MISCOP:
    BPF_TAX		= 0x00
    BPF_TXA		= 0x80

class BPFi(object):
    def __init__(self, c,t,f,k):
        self._raw_code = c 
        self.code = Code(c)
        self.jt = t 
        self.jf = f 
        self.k = k 

class BpfProcessorBase(processor_t):
    id = 0x8000 + 8888
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["bpf"]
    plnames = ["BPF"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
                'header': [".bpf"],
        "flag": AS_NCHRE | ASH_HEXF0 | ASD_DECF0 | ASO_OCTF0 | ASB_BINF0 | AS_NOTAB,
        "uflag": 0,
        "name": "b-p-f",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_dword": ".dword",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    
    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i

        # Create the ireg_XXXX constants
        for i in xrange(len(self.regNames)):
            setattr(self, 'ireg_' + self.regNames[i], i)

        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["M"]
    # ------------------------------------------------------------------------
    def _read_cmd_dword(self):
        ea = self.cmd.ea + self.cmd.size
        dword =get_full_long(ea)
        self.cmd.size += 4
        return dword

    def _read_cmd_word(self):
        ea = self.cmd.ea + self.cmd.size
        word =get_word(ea)
        self.cmd.size += 2
        return word

    def _read_cmd_byte(self):
        ea = self.cmd.ea + self.cmd.size
        byte = get_full_byte(ea)
        self.cmd.size += 1
        return byte

    # ------------------------------------------------------------------------

    def ana(self):
        return self._ana()

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(7) # instruction menm total len (before operands), padded with spaces
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)


class BpfProc(BpfProcessorBase):
    NEGATIVE_BRANCH = 0x00
    POSITIVE_BRANCH = 0x01
    M_BASE = 0x04
    FORCE_ENUM = 0x0b

    reg_names = regNames = [
        "A", "x", "len",
        #virutal 
        "CS", 
        "M"
    ]

    instruc = instrs = [

        # ALU
        { 'name': 'add', 'feature': CF_USE1 | CF_USE2 },
        { 'name': 'sub', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'mul', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'div', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'or', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'and', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'lsh', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'rsh', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'neg', 'feature': CF_USE1},
        { 'name': 'mod', 'feature': CF_USE1 | CF_USE2},
        { 'name': 'xor', 'feature': CF_USE1 | CF_USE2},
        
        # MISC
        { 'name': 'tax', 'feature': 0 },
        { 'name': 'txa', 'feature': 0 },
        
        # STORE
        { 'name': 'stx', 'feature': CF_USE1 | CF_CHG1},
        { 'name': 'st', 'feature': CF_USE1 | CF_CHG1},

        # LOAD
        { 'name': 'ldx', 'feature': CF_USE1 },
        { 'name': 'ld', 'feature': CF_USE1 },
        { 'name': 'ldh', 'feature': CF_USE1 },
        { 'name': 'ldb', 'feature': CF_USE1 },

        # BRANCH
        { 'name': 'jne', 'feature': CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jeq', 'feature':  CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jle', 'feature': CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jgt', 'feature': CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jlt', 'feature': CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jge', 'feature': CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jnset', 'feature':CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jset', 'feature':CF_STOP | CF_USE1 | CF_USE2 | CF_USE3},
        { 'name': 'jmp', 'feature':CF_STOP | CF_USE1},

        # RETURN
        { 'name': 'ret', 'feature': CF_STOP | CF_USE1},
    ]

    instruc_end = len(instruc)

    def _emu_operand(self, op, reads):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN

                # name label accordincly; can only be labels from branch instructions
                n = '@_{}'.format((op.addr-0x1000)/8)
                MakeNameEx(op.addr, n, SN_AUTO )
              
            if op.specval & BpfProc.POSITIVE_BRANCH: # green arrow
                ua_add_cref(0, op.addr, fl)
            else:
                
                if op.addr == cmd.ea + cmd.size:
                    ua_add_cref(0, op.addr, fl_F)
                else:                
                    ua_add_cref(0, op.addr, fl)
    def emu(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        for i,chng in enumerate([CF_CHG1, CF_CHG2, CF_CHG3]):
            op = self.cmd[i]
            if op.type == o_void:
                break
            
            self._emu_operand(op, ft & chng)
            # if op.specval & BpfProc.FORCE_ENUM:         
            #     seccomp_id = GetEnum('SECCOMP')
            #     cid = GetConst(seccomp_id, op.value, 0xFFFF0000)
            #     if cid != -1:
            #         OpEnum(self.cmd.ea, i, seccomp_id)

        if not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)

        return True
   
    def outop(self, op):
        if op.type == o_phrase:
            opv = op_t()
            opv.type = o_imm
            opv.value = 4
            OutValue(opv, OOFW_32 ) # no prefix
            out_symbol('*') 
            out_symbol('(') 
            out_symbol('[') 
            OutValue(op, OOFW_32 ) # no prefix
            out_symbol(']')
            out_symbol('&') 
            opv.value =0x0f
            OutValue(opv, OOFW_32 ) # no prefix
            out_symbol(')') 
            
            return True
        if op.type == o_displ:
            
            out_symbol('[') 
            out_register(self.regNames[op.reg])
            out_symbol('+') 
            OutValue(op, OOFW_32 ) # no prefix
            out_symbol(']')
            return True

        if op.type == o_reg:
            out_register(self.regNames[op.reg])
            return True

        if op.type == o_imm:
            # out_symbol('#') 
            OutValue(op, OOFW_32 ) # no prefix            
            # out_symbol(']')
            return True

        if op.type in [o_mem]:
            if op.specval  & BpfProc.M_BASE: # is scrath memory
                out_register('M') 
                
            out_symbol('[') 
            OutValue(op, OOF_ADDR ) # no prefix
            out_symbol(']')
            return True

        if op.type in [o_near]:
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
            return True
        
        return False
    
    def decode_ld(self, bi, cmd):
        c = bi.code
        isldx = c._class == BPF_CLASS.BPF_LDX
        if isldx:
            cmd.itype = self.inames['ldx']
        else:
            cmd.itype = self.inames['ld'+{
                BPF_SIZE.BPF_W:'',
                BPF_SIZE.BPF_H:'h',
                BPF_SIZE.BPF_B:'b'
            }[c._size]]
        if not isldx:
                
            if c._mode == BPF_MODE.BPF_ABS:
                cmd[0].type = o_mem            
                cmd[0].dtyp = dt_dword
                cmd[0].addr = bi.k
                return 1

            if c._mode == BPF_MODE.BPF_IND:
                cmd[0].type = o_displ            
                cmd[0].dtyp = dt_dword
                cmd[0].value = SIGNEXT(bi.k,32)
                cmd[0].reg = self.regNames.index('x')
                return 1
        
        else:
            if c._mode == BPF_MODE.BPF_MSH:
                cmd[0].type = o_phrase           
                cmd[0].dtyp = dt_dword
                cmd[0].value = SIGNEXT(bi.k,32)
                return 1
        
        if isldx or (not isldx and c._size == BPF_SIZE.BPF_W):
            if c._mode == BPF_MODE.BPF_IMM:
                cmd[0].type = o_imm            
                cmd[0].dtyp = dt_dword
                cmd[0].value = bi.k
                return 1

            if c._mode == BPF_MODE.BPF_LEN:
                cmd[0].type = o_reg            
                cmd[0].dtyp = dt_dword
                cmd[0].reg = self.regNames.index('len')
                return 1

            if c._mode == BPF_MODE.BPF_MEM:
                cmd[0].type = o_mem            
                cmd[0].dtyp = dt_dword
                cmd[0].addr = bi.k
                cmd[0].specval |= BpfProc.M_BASE # M as base
                return 1

    def decode_ret(self, bi, cmd):
        cmd.itype = self.inames['ret']
        if bi.code._rval == BPF_RVAL.BPF_K:
            cmd[0].type = o_imm            
            cmd[0].dtyp = dt_dword
            cmd[0].value = bi.k
            cmd[0].specval |= BpfProc.FORCE_ENUM
            # todo: defined values for seccomp?
        elif bi.code._rval == BPF_RVAL.BPF_A:
            cmd[0].type = o_reg            
            cmd[0].dtyp = dt_dword
            cmd[0].reg = self.regNames.index('A')
        else:
            pass # X not supported
        return 1

    def decode_jmp(self, bi, cmd):
        c = bi.code
        curr_off = cmd.ea + cmd.size

        cmd.itype = self.inames[{
            BPF_OP.BPF_JA:'jmp',
            BPF_OP.BPF_JEQ:'jeq',
            BPF_OP.BPF_JGE:'jge',
            BPF_OP.BPF_JGT:'jgt',
            BPF_OP.BPF_JSET:'jset'
        }[c._op]]

        if c._op == BPF_OP.BPF_JA: 
            cmd[0].type = o_near            
            cmd[0].dtyp = dt_dword
            cmd[0].addr = curr_off + bi.k* BPF_INST_SIZE
            return 1
        
        immi = 0
        jti = 1
        jfi = 2
        if bi.jt == 0: # if the true offset == 0, then use fake negative compares so arrows would be parsed correctly
            jfi = 1
            jti = 2

            cmd.itype = self.inames[{
            BPF_OP.BPF_JEQ:'jne',
            BPF_OP.BPF_JGE:'jlt',
            BPF_OP.BPF_JGT:'jle',
            BPF_OP.BPF_JSET:'jnset'
        }[c._op]]
                
        cmd[immi].type = o_imm             
        cmd[immi].dtyp = dt_dword
        cmd[immi].value = SIGNEXT(bi.k, 32)

        cmd[jti].type = o_near            
        cmd[jti].dtyp = dt_byte
        cmd[jti].addr = curr_off + bi.jt* BPF_INST_SIZE

        cmd[jfi].type = o_near            
        cmd[jfi].dtyp = dt_byte
        cmd[jfi].addr = curr_off + bi.jf* BPF_INST_SIZE

        if bi.jt == 0:
            # switch labels
            cmd[jti].specval = BpfProc.NEGATIVE_BRANCH
            cmd[jfi].specval = BpfProc.POSITIVE_BRANCH
        else:
            cmd[jti].specval = BpfProc.POSITIVE_BRANCH
            cmd[jfi].specval = BpfProc.NEGATIVE_BRANCH
        
        return 3

    def decode_misc(self, bi, cmd):
        c = bi.code
        
        cmd.itype = self.inames[
            {
                BPF_MISCOP.BPF_TAX: 'tax',
                BPF_MISCOP.BPF_TXA: 'txa'
            }[c._miscop]
        ]
        return 0

    def decode_store(self, bi, cmd):
        c = bi.code
        cmd.itype = self.inames[
            {
                BPF_CLASS.BPF_ST: 'st',
                BPF_CLASS.BPF_STX: 'stx'
            }[c._class]
         ]

        cmd[0].type = o_mem            
        cmd[0].dtyp = dt_dword
        cmd[0].addr = bi.k
        cmd[0].specval |= BpfProc.M_BASE # M as base

        return 1
    
    def decode_alu(self, bi, cmd):
        """
        BPF_ADD		= 0x00
        BPF_SUB		= 0x10
        BPF_MUL		= 0x20
        BPF_DIV		= 0x30
        BPF_OR		= 0x40
        BPF_AND		= 0x50
        BPF_LSH		= 0x60
        BPF_RSH		= 0x70
        BPF_NEG		= 0x80
        """
        c = bi.code
        cmd.itype = self.inames[{
            BPF_OP.BPF_ADD:'add',
            BPF_OP.BPF_SUB:'sub',
            BPF_OP.BPF_MUL:'mul',
            BPF_OP.BPF_DIV:'div',
            BPF_OP.BPF_OR:'or',
            BPF_OP.BPF_AND:'and',
            BPF_OP.BPF_LSH:'lsh',
            BPF_OP.BPF_RSH:'rsh',
            BPF_OP.BPF_NEG:'neg',
            BPF_OP.BPF_MOD:'mod',
            BPF_OP.BPF_XOR:'xor'

        }[c._op]]
    
        # assert bi.code._rval == BPF_RVAL.BPF_A
        cmd[0].type = o_reg            
        cmd[0].dtyp = dt_dword
        cmd[0].reg = self.regNames.index('A')

        if c._op != BPF_OP.BPF_NEG:
            if bi.code._src == BPF_RVAL.BPF_X:
                cmd[1].type = o_reg            
                cmd[1].dtyp = dt_dword
                cmd[1].reg = self.regNames.index('x')
            elif bi.code._src == BPF_RVAL.BPF_K:
                cmd[1].type = o_imm            
                cmd[1].dtyp = dt_dword
                cmd[1].value = bi.k
            else:
                assert False,  bi.code._rval
            return 2
        return 1

    def _ana(self):
        cmd = self.cmd
        c = self._read_cmd_word()
        jt = self._read_cmd_byte()
        jf = self._read_cmd_byte()
        k = self._read_cmd_dword()
        bi = BPFi(c, jt, jf, k)

        c = bi.code
        # print 'cls:{:02X} sz:{:02X} md:{:02X} op:{:02X} src:{:02X} rval:{:02X} misc:{:02X}'.format(
        #     c._class,
        #     c._size,
        #     c._mode,
        #     c._op,
        #     c._src,
        #     c._rval,
        #     c._miscop 
        # )
        op_count = 0
        if c._class == BPF_CLASS.BPF_MISC:
            op_count = self.decode_misc(bi, cmd)
            
        if c._class == BPF_CLASS.BPF_RET:
            op_count = self.decode_ret(bi, cmd)

        elif c._class in [BPF_CLASS.BPF_LD, BPF_CLASS.BPF_LDX]:
            op_count = self.decode_ld(bi, cmd)
            
        elif c._class == BPF_CLASS.BPF_JMP:
            op_count = self.decode_jmp(bi, cmd)

        elif c._class in [BPF_CLASS.BPF_ST, BPF_CLASS.BPF_STX]:
            op_count = self.decode_store(bi, cmd)
        
        elif c._class == BPF_CLASS.BPF_ALU:
            op_count = self.decode_alu(bi, cmd)
            
        cmd[op_count].dtyp = o_void # so that 'out' method would know when to stop
        return cmd.size


def PROCESSOR_ENTRY():
    return BpfProc()

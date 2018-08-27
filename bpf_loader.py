import idaapi
from idc import *


def read_whole_file(li, s=0):
    li.seek(s)
    return li.read(li.size())

def accept_file(li, n):
    # we support only one format per file
      
    if idaapi.IDA_SDK_VERSION < 700 and n > 0:
        return 0

    li.seek(0)
    if li.read(4) != 'bpf\0':
        return 0

    return {'format': "BPF file", 'options': 1|0x8000} # accept the file

# -----------------------------------------------------------------------

def setup_enums():
    
    enums = {'SECCOMP': [  #http://lxr.free-electrons.com/source/include/uapi/linux/seccomp.h#L28
        ('SECCOMP_RET_KILL', 0, 'kill the task immediately'),
        ('SECCOMP_RET_TRAP',  0x00030000, 'disallow and force a SIGSYS'),
        ('SECCOMP_RET_ERRNO', 0x00050000, 'returns an errno'),
        ('SECCOMP_RET_TRACE', 0x7ff00000, 'pass to a tracer or disallow'),
        ('SECCOMP_RET_ALLOW', 0x7fff0000, 'allow')
    ],
    'AUDIT_ARCH':[
        ('AUDIT_ARCH_I386', 0x40000003, ''),
        ('AUDIT_ARCH_X86_64', 0xC000003E, '')
    ]}

    for enum_name in enums:
        enum_vals = enums[enum_name]
        repeat_cmnt = 0
        enum_id = AddEnum(-1, enum_name, 0) # index -1 to append to list; bitmask 0

        if enum_id == BADADDR:
            print 'Unable to create enum SECCOMP'
            return -1

        for n,v,c in enum_vals:
            if AddConst(enum_id, n, v):
                print 'Unable to create {}'.format(n)
                return -1
            
            if c:
                const_id = GetConstByName(n)
                if const_id == -1:
                    print 'Unable to get id for {}'.format(n)
                    return -1

                
                if not SetConstCmt(const_id, c, repeat_cmnt):
                    print 'failed setting comment for {}'.format(n)
                    return -1

    print 'Finished creating enum'

def load_file(li, neflags, format):
    
    # Select the PC processor module
    idaapi.set_processor_type("BPF", SETPROC_ALL|SETPROC_FATAL)
    
    buf = read_whole_file(li, 8)
    if not buf:
        return 0

    start = 0x0
    seg = idaapi.segment_t()
    size = len(buf)
    end  = start + size
    
    # Create the segment
    seg.startEA = start
    seg.endEA   = end
    seg.bitness = 1 # 32-bit
    idaapi.add_segm_ex(seg, "bpf_c", "CODE", 0)

    # Copy the bytes
    idaapi.mem2base(buf, start, end)

    # add entry point
    idaapi.add_entry(start, start, "start", 1) 

    # add comment to beginning of disassembly
    idaapi.describe(start, True, "BPF bytecode disassembly")

    # Mark for analysis
    AutoMark(start, AU_CODE)

    setup_enums()
    return 1

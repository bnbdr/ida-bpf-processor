import argparse
import subprocess
from struct import pack


def get_args():
    parser = argparse.ArgumentParser(description="generate bpf file using tcpdump's output. run this on a linux machine")
    parser.add_argument('-o', dest='out',
                        help='bpf file output, ignore to print disassembly')
    parser.add_argument('-f', dest='fltr',
                        required=True,
                        help='capture filter to compile')

    args = parser.parse_args()
    return args

def generate_bpf_file(out_path, resp):

    with open(out_path, 'wb') as of:
        of.write(b'bpf\0' + '\0' * 4)  # header
        for l in resp.split('\n')[1:]:
            if not l:
                break
            code,jt,jf,k = l.split(' ')
            bts = pack('<HBBI', int(code), int(jt), int(jf), int(k))
            print bts.encode('hex')
            of.write(bts)
            


def cmpl(fltr, out_path):
    cmd_base = 'tcpdump -p -ni lo -d'
    if out_path:
        cmd_base += 'dd'
    
    cmd = '{} "{}"'.format(cmd_base, fltr)
    try:
        resp = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError:
        print 'failed running tcpdump'
        return 

    if not out_path:
        print resp
        return
    
    generate_bpf_file(out_path, resp)

if __name__ == '__main__':
    args = get_args()
    cmpl(args.fltr, args.out)

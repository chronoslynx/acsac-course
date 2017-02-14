#!/usr/bin/env python

from pprint import pprint

import angr

p = angr.Project("cfg_2")

# WRITEME: generate a CFG that collects data references during CFG recovery
# Note that by default it resolves indirect jumps (like jump tables)
cfg = p.analyses.CFGFast(collect_data_references=True)

# WRITEME: print out the recovered indirect jumps
indirect_jumps = cfg.indirect_jumps
print("Here are all indirect jumps from the binary:")
pprint(indirect_jumps)

# WRITEME: print out the recovered list of memory data
memory_data = cfg.memory_data
print("Here are all recovered memory data from the binary:")
pprint(memory_data)

# WRITEME: print out the reversed map between instruction addresses to memory data
ins_to_memdata = {v.insn_addr: v for v in memory_data.itervalues()}
print("Here is a mapping between instruction address and memory data:")
pprint(ins_to_memdata)

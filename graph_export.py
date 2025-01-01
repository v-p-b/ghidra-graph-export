# Export Function Graph to .dot files
# @runtime Jython

# based on code by cetfor: https://github.com/NationalSecurityAgency/ghidra/issues/855#issuecomment-569355675

import json
import tempfile
import os

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor


def collect_nodes(elist):
    ret = set()
    for f, t in elist:
        ret.add(f)
        ret.add(t)
    return ret


def address2name(addr):
    return "BB%s" % (str(addr))


def block_instructions_count(block):
    ret = 0
    for a in block.getAddresses(True):
        if getInstructionAt(a) != None:
            ret += 1
    return ret


def export_dot(name, elist, path):
    out_name = "%s.dot" % (name)
    out_path = os.path.join(path, out_name)
    with open(out_path, "w") as out:
        out.write("digraph %s {\n" % (name))
        out.write('  node [shape="box"];\n')
        out.write("  graph [splines=ortho];\n")
        for e in elist:
            f = e[0].getFirstStartAddress()
            t = e[1].getFirstStartAddress()
            out.write("  %s -> %s;\n" % (address2name(f), address2name(t)))
        out.write("}\n")
    print("Exported %s" % (out_path))


def export_json(name, elist, path):
    out_name = "%s.json" % (name)
    out_path = os.path.join(path, out_name)
    data = {}
    data["options"] = {"type": "directed", "multi": True, "allowSelfLoops": True}
    data["attributes"] = {}
    data["nodes"] = []
    data["edges"] = []
    nodes = collect_nodes(elist)

    for n in nodes:
        node_data = {}
        node_data["key"] = address2name(n.getFirstStartAddress())
        node_data["attributes"] = {}
        node_data["attributes"]["lines"] = block_instructions_count(n)
        data["nodes"].append(node_data)

    for s, t in elist:
        edge_data = {}
        edge_data["source"] = address2name(s.getFirstStartAddress())
        edge_data["target"] = address2name(t.getFirstStartAddress())
        edge_data["attributes"] = {}
        edge_data["attributes"]["type"] = "regular"  # TODO
        data["edges"].append(edge_data)

    with open(out_path, "w") as out:
        json.dump(data, out)

    print("Exported %s" % (out_path))


edge_list = []

blockModel = BasicBlockModel(currentProgram)
monitor = ConsoleTaskMonitor()
func = getFunctionContaining(currentAddress)
funcName = func.getName()

tmpDir = tempfile.gettempdir()

print("Basic block details for function '{}':".format(funcName))
blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)

while blocks.hasNext():
    bb = blocks.next()
    dest = bb.getDestinations(monitor)
    while dest.hasNext():
        dbb = dest.next()
        if not getFunctionAt(dbb.getDestinationAddress()):
            edge_list.append((dbb.getSourceBlock(), dbb.getDestinationBlock()))

export_dot(funcName, edge_list, tmpDir)
export_json(funcName, edge_list, tmpDir)

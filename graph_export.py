# Export Function Graph to .dot files
# @runtime Jython

# based on code by cetfor: https://github.com/NationalSecurityAgency/ghidra/issues/855#issuecomment-569355675

import tempfile
import os

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor


def export_dot(name, elist, path):
    outName = "%s.dot" % (name)
    outPath = os.path.join(path, outName)
    with open(outPath, "w") as out:
        out.write("digraph %s {\n" % (name))
        out.write('  node [shape="box"];\n')
        out.write("  graph [splines=ortho];\n")
        for e in elist:
            f = str(e[0].getFirstStartAddress())
            t = str(e[1].getFirstStartAddress())
            out.write("  BB%s -> BB%s;\n" % (f, t))
        out.write("}\n")
    print("Exported %s" % (outPath))


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

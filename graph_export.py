# Export Function Graph to .dot files
# @runtime Jython


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


def get_color(source, target):
    if source.getNumDestinations(monitor) < 2:
        return "regular"
    i = getInstructionContaining(source.getMaxAddress())
    if i.getFallThrough() is None:  # Unconditional branch as last decoded instruction
        return "regular"
    if i.getFallThrough().equals(target.getFirstStartAddress()):
        return "alternative"
    # TODO do some sanity checks, the CodeBlock abstraction is weird...
    return "consequence"


def get_color_dot(source, target):
    color = get_color(source, target)
    if color == "regular":
        return "blue"
    elif color == "alternative":
        return "red"
    return "green"


def export_dot(name, elist):
    out = []
    out.append("digraph %s {" % (name))
    out.append('  node [shape="box"];')
    out.append("  graph [splines=ortho];")
    for e in elist:
        f = e[0].getFirstStartAddress()
        t = e[1].getFirstStartAddress()
        out.append(
            '  %s -> %s [color="%s"];'
            % (address2name(f), address2name(t), get_color_dot(e[0], e[1]))
        )
    out.append("}")
    return "\n".join(out)

name_counter = 0
def normalize_func_name(name):
    global name_counter
    ret = name.replace('/','-').replace('\\','-').replace('<', '_').replace('>', '_').replace('=','_').replace(',','-')
    if len(ret) > 128:
        ret=ret[0:128]+"~"+str(name_counter)
        name_counter+=1
    return ret

def export_json(name, elist):
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
        edge_data["attributes"]["type"] = get_color(s, t)
        data["edges"].append(edge_data)

    return json.dumps(data)

blockModel = BasicBlockModel(currentProgram)
monitor = ConsoleTaskMonitor()

tmpDir = tempfile.gettempdir()
binName = os.path.basename(getCurrentProgram().getExecutablePath())
binHash = getCurrentProgram().getExecutableSHA256()
binDir = os.path.join(tmpDir, "ghidra_export", binName)
os.makedirs(binDir)

all_json = []

func = getFirstFunction()
while func is not None:
    if func.isExternal() or func.isThunk():
        func = getFunctionAfter(func)
        continue

    funcName = func.getName()
    edge_list = []

    print("[*] Parsing %s" % (funcName))
    # based on code by cetfor: https://github.com/NationalSecurityAgency/ghidra/issues/855#issuecomment-569355675
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)

    while blocks.hasNext():
        bb = blocks.next()
        dest = bb.getDestinations(monitor)
        while dest.hasNext():
            dbb = dest.next()
            if not getFunctionAt(dbb.getDestinationAddress()):
                edge_list.append((dbb.getSourceBlock(), dbb.getDestinationBlock()))

    dot_export = export_dot(funcName, edge_list)
    json_export = export_json(funcName, edge_list)

    all_json.append(json.loads(json_export)) # TODO Wasteful, need refactoring

    dot_path = os.path.join(binDir, "%s.dot" % normalize_func_name(funcName))
    with open(dot_path, "w") as out:
        out.write(dot_export)
    print(" \_ Written %s" % (dot_path))

    json_path = os.path.join(binDir, "%s.json" % normalize_func_name(funcName))
    with open(json_path, "w") as out:
        out.write(json_export)
    print(" \_ Written %s" % (json_path))

    func = getFunctionAfter(func)

meta_json_path = os.path.join(binDir, "_ghidra_export_metadata.json")
with open(meta_json_path, "w") as out:
    meta_json = {}
    meta_json["attributes"] = {}
    meta_json["attributes"]["binary_name"] = binName
    meta_json["attributes"]["binary_hash"] = binHash
    out.write(json.dumps(meta_json))
print("[*] Metadata JSON written: %s" % (meta_json_path))

full_json_path=os.path.join(binDir, "full.json")
with open(full_json_path, "w") as out:
    full_json={}
    full_json["attributes"]={}
    full_json["attributes"]["binary_name"]=binName
    full_json["attributes"]["binary_hash"]=binHash
    full_json["functions_graphology"]=all_json
    out.write(json.dumps(full_json))
print("Full JSON written: %s" % (full_json_path))

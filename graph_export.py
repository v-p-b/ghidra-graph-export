# Export Function Graph to .dot files
# @runtime Jython


import json
import tempfile
import os

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

BULK_JSON_EXPORT = False


def collect_nodes(elist):
    ret = set()
    for f, t in elist:
        ret.add(f)
        if t is not None:
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
    for f, t in elist:
        if t is None: continue
        f_addr = f.getFirstStartAddress()
        t_addr = t.getFirstStartAddress()
        out.append(
            '  %s -> %s [color="%s"];'
            % (address2name(f_addr), address2name(t_addr), get_color_dot(f, t))
        )
    out.append("}")
    return "\n".join(out)


name_counter = 0


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
        if t is None: continue
        edge_data = {}
        edge_data["source"] = address2name(s.getFirstStartAddress())
        edge_data["target"] = address2name(t.getFirstStartAddress())
        edge_data["attributes"] = {}
        edge_data["attributes"]["type"] = get_color(s, t)
        data["edges"].append(edge_data)

    return data


blockModel = BasicBlockModel(currentProgram)
monitor = ConsoleTaskMonitor()

bin_name = os.path.basename(getCurrentProgram().getExecutablePath())
bin_hash = getCurrentProgram().getExecutableSHA256()

project_name = bin_name
if "GHIDRA_EXPORT_PROJECT" in os.environ:
    project_name = os.environ["GHIDRA_EXPORT_PROJECT"]

bin_version = bin_hash
if "GHIDRA_EXPORT_VERSION" in os.environ:
    bin_version = os.environ["GHIDRA_EXPORT_VERSION"]


base_dir = os.path.join(tempfile.gettempdir(), "ghidra_export")
if "GHIDRA_EXPORT_OUTDIR" in os.environ:
    base_dir = os.environ["GHIDRA_EXPORT_OUTDIR"]

bin_dir = os.path.join(base_dir, project_name)
os.makedirs(bin_dir)

all_json = []
func_index = []

func = getFirstFunction()
while func is not None:
    if func.isExternal() or func.isThunk():
        func = getFunctionAfter(func)
        continue

    func_name = func.getName()
    entry_str = str(func.getEntryPoint())
    edge_list = []

    print("[*] Parsing %s" % (func_name))
    # based on code by cetfor: https://github.com/NationalSecurityAgency/ghidra/issues/855#issuecomment-569355675
    blocks = blockModel.getCodeBlocksContaining(func.getBody(), monitor)

    while blocks.hasNext():
        bb = blocks.next()
        dest = bb.getDestinations(monitor)
        while dest.hasNext():
            dbb = dest.next()
            if not getFunctionAt(dbb.getDestinationAddress()):
                edge_list.append((dbb.getSourceBlock(), dbb.getDestinationBlock()))
        if (len(edge_list) == 0): # Always add the entry block
            edge_list.append((bb, None))

    dot_export = export_dot(func_name, edge_list)
    json_export = export_json(func_name, edge_list)

    func_index.append(
        {
            "address": entry_str,
            "name": func_name,
            "node_count": len(json_export["nodes"]),
        }
    )
    if BULK_JSON_EXPORT:
        all_json.append(json.loads(json_export))  # TODO Wasteful, need refactoring

    dot_path = os.path.join(bin_dir, "%s.dot" % (entry_str))
    with open(dot_path, "w") as out:
        out.write(dot_export)
    print(" \_ Written %s" % (dot_path))

    json_path = os.path.join(bin_dir, "%s.json" % (entry_str))
    with open(json_path, "w") as out:
        json.dump(json_export, out, sort_keys=True, indent=2)
    print(" \_ Written %s" % (json_path))

    func = getFunctionAfter(func)

meta_json_path = os.path.join(bin_dir, "index.json")
with open(meta_json_path, "w") as out:
    meta_json = {
        "index_type": "ghidra",
        "project": project_name,
        "filename": bin_name,
        "version": bin_version,
        "sha256": bin_hash,
        "functions": func_index,
        "extra": {},
    }
    json.dump({"version": 1, "content": meta_json}, out, sort_keys=True, indent=2)
print("[*] Metadata JSON written: %s" % (meta_json_path))

if BULK_JSON_EXPORT:
    full_json_path = os.path.join(bin_dir, "full.json")
    with open(full_json_path, "w") as out:
        full_json = {}
        full_json["attributes"] = {}
        full_json["attributes"]["binary_name"] = bin_name
        full_json["attributes"]["binary_hash"] = bin_hash
        full_json["functions_graphology"] = all_json
        out.write(json.dumps(full_json, sort_keys=True, indent=2))
    print("Full JSON written: %s" % (full_json_path))

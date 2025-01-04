# Ghidra Graph Export Script

Generate Graphviz (DOT) and Grapholoy graphs from ghidra functions.

Headless execution:

```bash
./support/analyzeHeadless /path/to/project \
                          project_name/folder1/folder2 \
                          -process binary_name \
                          -postScript /path/to/graph_export.py
```

## Environment

* `GHIDRA_EXPORT_PROJECT` - Project name: Default: binary file name (from Ghidra)
* `GHIDRA_EXPORT_VERSION` - Binary version (e.g. from exiftool). Default: SHA256 of the binary.
* `GHIDRA_EXPORT_OUTDIR` - Output base directory. Default: `<system temp>/ghidra_exports`.
 


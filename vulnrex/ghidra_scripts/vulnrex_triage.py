# vulnrex_triage.py
# Ghidra headless post-script.
#
# Run via analyzeHeadless ... -postScript vulnrex_triage.py <output_json_path>
# Ghidra's script engine for .py scripts is Jython (2.7), NOT Python 3 --
# keep this file Jython-compatible (no f-strings, no walrus, etc).
#
# Dumps a lightweight triage summary of the just-analyzed program:
#   - defined functions (name, entry point)
#   - imported/external symbols
#   - defined strings
# to a JSON file that VulnREX's re_module.py reads back into the GUI/report.

import json

from ghidra.program.model.symbol import SymbolType


def get_output_path():
    args = getScriptArgs()
    if not args:
        raise Exception("vulnrex_triage.py requires an output path argument")
    return args[0]


def collect_functions(limit=500):
    out = []
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    count = 0
    while it.hasNext() and count < limit:
        f = it.next()
        out.append({
            "name": f.getName(),
            "entry": f.getEntryPoint().toString(),
            "is_external": f.isExternal(),
        })
        count += 1
    return out


def collect_imports(limit=500):
    out = []
    st = currentProgram.getSymbolTable()
    it = st.getExternalSymbols()
    count = 0
    while it.hasNext() and count < limit:
        sym = it.next()
        if sym.getSymbolType() in (SymbolType.FUNCTION, SymbolType.LABEL):
            out.append(sym.getName())
        count += 1
    return sorted(set(out))


def collect_strings(limit=300):
    out = []
    listing = currentProgram.getListing()
    data_it = listing.getDefinedData(True)
    count = 0
    while data_it.hasNext() and count < limit:
        d = data_it.next()
        if d.hasStringValue():
            try:
                val = d.getValue()
                s = str(val) if val is not None else None
            except Exception:
                s = None
            if s and len(s) >= 4:
                out.append(s)
                count += 1
    return out


def main():
    output_path = get_output_path()
    program_name = currentProgram.getName()
    language = str(currentProgram.getLanguage().getLanguageID())

    result = {
        "program_name": program_name,
        "language": language,
        "functions": collect_functions(),
        "imports": collect_imports(),
        "strings": collect_strings(),
    }

    with open(output_path, "w") as fh:
        fh.write(json.dumps(result, indent=2))


main()

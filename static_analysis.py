import subprocess
import math
import pefile  # parse PE headers
from collections import Counter
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection


def run_file(filepath):
    out = subprocess.run(["file",filepath], capture_output=True, text=True)
    # remove the path from output
    return out.stdout.split(":", 1)[-1].strip()

def get_hash(filepath):
    out = subprocess.run(["sha256sum", filepath],capture_output=True, text=True)
    return out.stdout.split(" ")[0]


def run_strings(filepath, minlen: int = 6):
    out = subprocess.run(["strings", "-n", str(minlen), filepath], capture_output=True, text=True)
    return out.stdout.splitlines()

def calc_entropy(filepath):
    # Calculate Shannon Entropy
    with open(filepath, "rb") as f:
        data = f.read()
    if not data:
        return 0.0
    # Counts frequency of each byte as dict
    counter = Counter(data)
    entropy = -sum(
        (count / len(data)) * math.log2(count / len(data))
        for count in counter.values()
    )
    return round(entropy, 3)

def get_elf_imports(filepath):
    # Extract imported DLLs and functions from elf binaries
    try:
        with open(filepath, "rb") as f:
            elf = ELFFile(f)
            imports = []
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            imports.append(tag.needed)
            return imports
    except Exception:
        return []
    
def get_pe_imports(filepath):
     # Extract imported DLLs and functions from .exe / .dll
    try:
        pe = pefile.PE(filepath)
        imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            for imp in entry.imports:
                if imp.name:
                    imports.append(f"{dll}::{imp.name.decode()}\n")
        return imports
    except Exception:
        return []

def get_imports(filepath):
    pe_imports = get_pe_imports(filepath)
    if pe_imports:
        return pe_imports
    return get_elf_imports(filepath)  

def interpret_entropy(entropy):
    if entropy < 3.0:
        return f"{entropy} / 8.0 —> very low (sparse data or text)"
    elif entropy < 6.0:
        return f"{entropy} / 8.0 —> normal (standard compiled binary)"
    elif entropy < 7.0:
        return f"{entropy} / 8.0 —> elevated (possible compression)"
    else:
        return f"{entropy} / 8.0 —> high (likely packed or encrypted)"

def extract_features(filepath):
    return {
        "file": run_file(filepath),
        "strings": run_strings(filepath),
        "entropy": calc_entropy(filepath),
        "imports": get_imports(filepath),
        "hash": get_hash(filepath),
    }
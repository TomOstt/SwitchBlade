#!/usr/bin/env python3
"""M7: firmware diff engine. compare two firmware versions, find what Nintendo patched.
usage: python3 diff.py <dir_20.1.5> <dir_20.5.0>"""
import sys, os, glob, hashlib, difflib
from loader import NSO
from analyzer import get_service_name, target_value, scan_syscalls
from cfg import disassemble, find_functions, find_function_bounds


def load_dir(d):
    """load all NSOs from a directory → {service_name: nso}"""
    services = {}
    for path in glob.glob(os.path.join(d, "*.nso")):
        nso = NSO(path)
        name = get_service_name(nso) or os.path.basename(path).replace(".nso", "")
        services[name] = nso
    return services

def match_services(dir_old, dir_new):
    """pair NSOs across firmware versions by service name."""
    old = load_dir(dir_old)
    new = load_dir(dir_new)
    matched = {name: (old[name], new[name]) for name in old if name in new}
    added = set(new) - set(old)
    removed = set(old) - set(new)
    return matched, added, removed

def diff_services(matched):
    """compare raw .text bytes of each paired service."""
    unchanged, modified = [], []
    for name, (nso_old, nso_new) in matched.items():
        if nso_old.text == nso_new.text:
            unchanged.append(name)
        else:
            modified.append(name)
    return unchanged, modified

def get_bounds(nso):
    ins = disassemble(nso.text)
    return find_function_bounds(ins, find_functions(ins))

def hash_func(text, s, e):
    return hashlib.sha256(text[s:e]).hexdigest()

def diff_functions(nso_old, nso_new):
    """find which functions changed between two versions of the same service."""
    bo, bn = get_bounds(nso_old), get_bounds(nso_new)
    unchanged, modified = [], []
    for (so, eo), (sn, en) in zip(bo, bn):
        if hash_func(nso_old.text, so, eo) == hash_func(nso_new.text, sn, en):
            unchanged.append(so)
        else:
            modified.append((so, sn))
    added = [s for s, _ in bn[len(bo):]]
    removed = [s for s, _ in bo[len(bn):]]
    return unchanged, modified, added, removed

def diff_instructions(nso_old, nso_new, start_old, end_old, start_new, end_new):
    """diff two versions of a modified function at the instruction level."""
    ins_old = disassemble(nso_old.text)
    ins_new = disassemble(nso_new.text)
    lines_old = [f"{i.mnemonic} {i.op_str}" for i in ins_old if start_old <= i.address < end_old]
    lines_new = [f"{i.mnemonic} {i.op_str}" for i in ins_new if start_new <= i.address < end_new]
    diff = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, lines_old, lines_new).get_opcodes():
        if tag == 'equal':
            for line in lines_old[i1:i2]:
                diff.append(('=', line))
        elif tag == 'replace':
            for line in lines_old[i1:i2]:
                diff.append(('-', line))
            for line in lines_new[j1:j2]:
                diff.append(('+', line))
        elif tag == 'delete':
            for line in lines_old[i1:i2]:
                diff.append(('-', line))
        elif tag == 'insert':
            for line in lines_new[j1:j2]:
                diff.append(('+', line))
    return diff

def print_diff_report(unchanged, modified, added, removed, matched, dir_old, dir_new):
    """print the full diff report."""
    print(f"\nFIRMWARE DIFF: {os.path.basename(dir_old.rstrip('/'))} → {os.path.basename(dir_new.rstrip('/'))}")
    print("=" * 60)
    print(f"  unchanged: {len(unchanged)} services")
    print(f"  modified:  {len(modified)} services")
    print(f"  added:     {len(added)} services")
    print(f"  removed:   {len(removed)} services")

    if added:
        print(f"\n  NEW SERVICES: {', '.join(sorted(added))}")
    if removed:
        print(f"\n  REMOVED SERVICES: {', '.join(sorted(removed))}")

    for name in sorted(modified):
        nso_old, nso_new = matched[name]
        syscalls = scan_syscalls(nso_old)
        tv = target_value(name, syscalls)
        print(f"\n{'─' * 60}")
        print(f"  {name}  (target_value: {tv}/10)")
        print(f"  .text: {len(nso_old.text)} → {len(nso_new.text)} bytes")

        func_unch, func_mod, func_add, func_rem = diff_functions(nso_old, nso_new)
        print(f"  functions: {len(func_unch)} unchanged, {len(func_mod)} modified, {len(func_add)} added, {len(func_rem)} removed")

        for addr_old, addr_new in func_mod[:5]:
            bo = get_bounds(nso_old)
            bn = get_bounds(nso_new)
            end_old = next(e for s, e in bo if s == addr_old)
            end_new = next(e for s, e in bn if s == addr_new)
            print(f"\n    MODIFIED func_0x{addr_old:x} → func_0x{addr_new:x}")
            changes = diff_instructions(nso_old, nso_new, addr_old, end_old, addr_new, end_new)
            for tag, line in changes:
                if tag != '=':
                    print(f"      {tag} {line}")


if __name__ == "__main__":
    dir_old = sys.argv[1]
    dir_new = sys.argv[2]

    print("loading firmware versions...")
    matched, added_services, removed_services = match_services(dir_old, dir_new)
    print(f"matched {len(matched)} services")
    unchanged, modified = diff_services(matched)
    print_diff_report(unchanged, modified, added_services, removed_services, matched, dir_old, dir_new)

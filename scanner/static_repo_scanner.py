#!/usr/bin/env python3
import argparse
import ast
import json
import re
import sys
import hashlib
from pathlib import Path
from typing import List, Set, Dict, Any

BINARY_CHECK_BYTES = 1024
CHUNK_SIZE = 8192

DEFAULT_DANGEROUS_REGEX = [
    r"\bcurl\s+.*\|\s*bash\b",
    r"\bwget\s+.*\|\s*sh\b",
    r"\bcurl\s+-LO\b",
    r"\bbase64\s+-d\b",
    r"\brm\s+-rf\s+/\b",
    r"\brm\s+-rf\s+\.\b",
    r"\bchmod\s+777\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bpython\s+-c\b",
    r"\bperl\s+-e\b",
    r"\bnc\s+-l\b",
    r"\bncat\b",
    r"\bssh\b",
    r"\bscp\b",
    r"\bopenssl\b",
]

DEFAULT_SUSPICIOUS_IMPORTS = {
    "socket", "ftplib", "telnetlib", "paramiko", "subprocess", "shlex",
    "pty", "pexpect", "ctypes", "urllib", "urllib.request", "requests",
    "os", "sys"
}

SUSPICIOUS_CALLS = {
    "eval", "exec", "execfile", "system", "popen", "Popen", "spawn"
}

EXCLUDE_DIRS_DEFAULT = {".git", "node_modules", "__pycache__", "venv", ".venv"}

def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def is_likely_text(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(BINARY_CHECK_BYTES)
            return chunk.count(b"\x00") == 0
    except Exception:
        return False

def scan_file_regex(path: Path, patterns: List[str]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    for pat in patterns:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            ctx = text[start:end].replace("\n", " ")
            findings.append({"pattern": pat, "match": m.group(0), "context": ctx[:200]})
    return findings

def extract_name_from_attribute(node: ast.Attribute) -> str:
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts)

def analyze_python_ast(path: Path) -> Dict[str, Any]:
    findings: Dict[str, Any] = {"imports": [], "danger_calls": []}
    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src, filename=str(path))
    except Exception:
        return findings
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                findings["imports"].append(n.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for n in node.names:
                if module:
                    findings["imports"].append(f"{module}.{n.name}")
                else:
                    findings["imports"].append(n.name)
        elif isinstance(node, ast.Call):
            func = node.func
            fname = None
            if isinstance(func, ast.Name):
                fname = func.id
            elif isinstance(func, ast.Attribute):
                try:
                    fname = extract_name_from_attribute(func)
                except Exception:
                    # fallback: try simple attr
                    if hasattr(func, "attr"):
                        fname = func.attr
            if fname:
                lower_fname = fname.lower()
                for bad in SUSPICIOUS_CALLS:
                    bad_lower = bad.lower()
                    if lower_fname == bad_lower or lower_fname.endswith("." + bad_lower) or bad_lower in lower_fname:
                        findings["danger_calls"].append({"call": fname, "lineno": getattr(node, "lineno", None)})
                        break
    return findings

def should_exclude(path: Path, base: Path, exclude_dirs: Set[str]) -> bool:
    try:
        rel = path.relative_to(base)
    except Exception:
        return False
    for part in rel.parts:
        if part in exclude_dirs:
            return True
    return False

def normalize_import_matches(imports: Set[str], suspicious: Set[str]) -> List[str]:
    bad = []
    for imp in imports:
        for si in suspicious:
            if imp == si or imp.startswith(si + "."):
                bad.append(imp)
                break
    return sorted(set(bad))

def scan_repo(path: Path, *,
              dangerous_patterns: List[str],
              suspicious_imports: Set[str],
              exclude_dirs: Set[str],
              verbose: bool = False) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "repo_path": str(path),
        "total_files": 0,
        "binary_files": [],
        "text_suspicious": [],
        "python_analysis": [],
    }

    for p in path.rglob("*"):
        if not p.is_file():
            continue
        if should_exclude(p, path, exclude_dirs):
            if verbose:
                print(f"Skipping excluded: {p}")
            continue

        report["total_files"] += 1
        rel = str(p.relative_to(path))
        try:
            if not is_likely_text(p):
                try:
                    h = sha256_of_file(p)
                except Exception:
                    h = None
                report["binary_files"].append({"path": rel, "sha256": h})
                continue
        except Exception:
            report["text_suspicious"].append({"path": rel, "issue": "read_error"})
            continue

        text_find = scan_file_regex(p, dangerous_patterns)
        if text_find:
            report["text_suspicious"].append({"path": rel, "matches": text_find})

        if p.suffix.lower() == ".py":
            ast_find = analyze_python_ast(p)
            imports = set(ast_find.get("imports", []))
            imported_bad = normalize_import_matches(imports, suspicious_imports)
            danger_calls = ast_find.get("danger_calls", [])
            if imported_bad or danger_calls:
                report["python_analysis"].append({
                    "path": rel,
                    "imports": imported_bad,
                    "danger_calls": danger_calls
                })

    return report

def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Static repository scanner")
    ap.add_argument("path", type=Path, help="Caminho para o repositório")
    ap.add_argument("--out", "-o", default="static_scan_report.json", help="Arquivo JSON de saída")
    ap.add_argument("--exclude", "-e", nargs="*", default=[], help="Diretórios a excluir (relativos ao repo)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Mostrar progresso")
    ap.add_argument("--add-pattern", action="append", default=[], help="Adicionar regex perigosa")
    ap.add_argument("--add-import", action="append", default=[], help="Adicionar import suspeito")
    return ap.parse_args(argv)

def main(argv: List[str]) -> int:
    args = parse_args(argv)
    repo = args.path.resolve()
    if not repo.exists() or not repo.is_dir():
        print("Caminho inválido:", repo)
        return 2

    dangerous_patterns = DEFAULT_DANGEROUS_REGEX.copy()
    if args.add_pattern:
        dangerous_patterns.extend(args.add_pattern)

    suspicious_imports = set(DEFAULT_SUSPICIOUS_IMPORTS)
    if args.add_import:
        suspicious_imports.update(args.add_import)

    exclude_dirs = set(EXCLUDE_DIRS_DEFAULT)
    if args.exclude:
        exclude_dirs.update(args.exclude)

    report = scan_repo(repo,
                       dangerous_patterns=dangerous_patterns,
                       suspicious_imports=suspicious_imports,
                       exclude_dirs=exclude_dirs,
                       verbose=args.verbose)

    outp = Path(args.out)
    try:
        outp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        print("Erro ao salvar relatório:", e)
        return 3

    print("Relatório salvo em:", outp)
    print("Arquivos totais:", report["total_files"])
    print("Binários detectados:", len(report["binary_files"]))
    print("Arquivos com padrões suspeitos (texto):", len(report["text_suspicious"]))
    print("Arquivos Python com imports/calls suspeitos:", len(report["python_analysis"]))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
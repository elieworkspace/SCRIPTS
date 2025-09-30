#!/usr/bin/env python3
"""
json_schema_inspect.py

Affiche la structure profonde (schema-like) d'un fichier JSON sans afficher les données réelles.
- Ne développe pas les listes : affiche la structure des éléments (échantillonnés).
- Peut échantillonner N éléments d'une liste pour construire une structure unifiée.
- Option --stream pour lire un grand fichier dont la racine est un tableau (utilise ijson).
"""

import json
import argparse
import logging
import os
import sys
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def type_name(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int) and not isinstance(v, bool):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "str"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, list):
        return "list"
    return type(v).__name__


def merge_structs(a, b):
    """Fusionne deux structures produites par analyze_value en une structure unifiée."""
    if a == b:
        return a
    # If both are basic type names (strings)
    if isinstance(a, str) and isinstance(b, str):
        if a == b:
            return a
        return sorted(list({a, b}))
    # If one is a union list
    if isinstance(a, list) and not isinstance(b, list):
        return merge_structs_union(a, b)
    if isinstance(b, list) and not isinstance(a, list):
        return merge_structs_union(b, a)
    if isinstance(a, list) and isinstance(b, list):
        # merge unions
        out = a[:]
        for item in b:
            found = False
            for i, existing in enumerate(out):
                out[i] = merge_structs(existing, item)
                found = True
            if not found:
                out.append(item)
        # try to flatten duplicates
        unique = []
        for item in out:
            if item not in unique:
                unique.append(item)
        return unique
    # If both are dicts (objects)
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a.keys()) | set(b.keys())
        merged = {}
        for k in sorted(keys):
            if k in a and k in b:
                merged[k] = merge_structs(a[k], b[k])
            elif k in a:
                merged[k] = a[k]
            else:
                merged[k] = b[k]
        return merged
    # If types differ, return union
    return sorted(list({repr(a), repr(b)}))


def merge_structs_union(lst, other):
    # lst is list (union), other is single structure
    out = []
    added = False
    for item in lst:
        out.append(merge_structs(item, other))
        added = True
    if not added:
        out.append(other)
    # dedupe
    unique = []
    for item in out:
        if item not in unique:
            unique.append(item)
    return unique


def analyze_value(value, max_depth=10, max_sample=5, depth=0):
    """Renvoie une structure représentant la forme du value."""
    if depth >= max_depth:
        return "..."  # profondeur atteinte

    t = type_name(value)

    if t in ("null", "bool", "int", "float", "str"):
        return t

    if t == "object":
        result = {}
        for k, v in value.items():
            result[k] = analyze_value(v, max_depth=max_depth, max_sample=max_sample, depth=depth + 1)
        return result

    if t == "list":
        # Si liste vide
        if len(value) == 0:
            return {"list": "empty"}
        # Échantillonner jusqu'à max_sample éléments
        sample = value[:max_sample]
        # Construire la structure unifiée des éléments
        elem_struct = analyze_value(sample[0], max_depth=max_depth, max_sample=max_sample, depth=depth + 1)
        for item in sample[1:]:
            s = analyze_value(item, max_depth=max_depth, max_sample=max_sample, depth=depth + 1)
            elem_struct = merge_structs(elem_struct, s)
        # Indique si la liste a plus d'éléments que l'échantillon
        more = len(value) > max_sample
        return {"list_of": elem_struct, "sampled": len(sample), "total_estimated": len(value), "more": more}

    return t


def print_tree(struct, indent=0):
    pad = "  " * indent
    if isinstance(struct, str):
        print(f"{pad}{struct}")
    elif isinstance(struct, list):
        # union types
        print(f"{pad}union:")
        for s in struct:
            print_tree(s, indent + 1)
    elif isinstance(struct, dict):
        # special-case list_of
        if "list_of" in struct and set(struct.keys()) >= {"list_of", "sampled", "total_estimated", "more"}:
            more = " (+more)" if struct.get("more", False) else ""
            print(f"{pad}list[{struct.get('sampled')}] ->")
            print_tree(struct["list_of"], indent + 1)
            return
        # normal object
        for k, v in struct.items():
            print(f"{pad}{k}: ", end="")
            # if primitive show inline
            if isinstance(v, (str, int)) or (isinstance(v, dict) and "list_of" in v):
                if isinstance(v, str):
                    print(v)
                else:
                    print()
                    print_tree(v, indent + 1)
            else:
                print()
                print_tree(v, indent + 1)
    else:
        print(f"{pad}{repr(struct)}")


def analyze_from_file(path, max_depth=10, max_sample=5, use_stream=False):
    if not os.path.isfile(path):
        logging.error("Fichier introuvable: %s", path)
        return None
    # Option streaming pour root array
    if use_stream:
        try:
            import ijson
        except Exception as e:
            logging.error("Option --stream requiert ijson (pip install ijson). Erreur: %s", e)
            return None
        with open(path, "rb") as f:
            # detect root type by reading first event
            parser = ijson.parse(f)
            try:
                prefix, event, value = next(parser)
            except StopIteration:
                logging.error("Fichier vide ou non JSON")
                return None
            # if root is start_array -> sample items
            if event == "start_array":
                # reset file pointer and iterate items
                f.seek(0)
                items = ijson.items(f, "item")
                sampled = []
                total = 0
                for i, it in enumerate(items):
                    total += 1
                    if i < max_sample:
                        sampled.append(it)
                    else:
                        # keep counting
                        continue
                if total == 0:
                    return {"list": "empty"}
                # analyze sample to produce element structure
                elem_struct = analyze_value(sampled[0] if sampled else {}, max_depth=max_depth, max_sample=max_sample, depth=0)
                for it in sampled[1:]:
                    elem_struct = merge_structs(elem_struct, analyze_value(it, max_depth=max_depth, max_sample=max_sample, depth=0))
                return {"list_of": elem_struct, "sampled": len(sampled), "total_estimated": total, "more": total > max_sample}
            else:
                logging.error("--stream ne supporte que les fichiers JSON dont la racine est un array.")
                return None

    # Non-stream: charger en mémoire (pour fichiers raisonnables)
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            logging.error("JSON mal formé: %s", e)
            return None
    return analyze_value(data, max_depth=max_depth, max_sample=max_sample, depth=0)


def main():
    parser = argparse.ArgumentParser(description="Afficher la structure profonde d'un fichier JSON (sans afficher les données).")
    parser.add_argument("json_file", help="Chemin du fichier JSON")
    parser.add_argument("--max-depth", type=int, default=10, help="Profondeur maximale à explorer (défaut 10)")
    parser.add_argument("--max-sample", type=int, default=5, help="Nombre d'éléments d'une liste à échantillonner (défaut 5)")
    parser.add_argument("--stream", action="store_true", help="Utiliser ijson pour parcourir un grand tableau racine sans tout charger (racine doit être un array)")
    parser.add_argument("--json-output", action="store_true", help="Sortie au format JSON (plutôt qu'arbre lisible)")
    args = parser.parse_args()

    struct = analyze_from_file(args.json_file, max_depth=args.max_depth, max_sample=args.max_sample, use_stream=args.stream)
    if struct is None:
        sys.exit(2)

    if args.json_output:
        print(json.dumps(struct, indent=2, ensure_ascii=False))
    else:
        print(f"Structure du fichier: {args.json_file}")
        print_tree(struct)


if __name__ == "__main__":
    main()

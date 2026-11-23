"""DEX binding and bounded data slicing for statically declared HTTP bodies."""

from functools import lru_cache
import json
from urllib.parse import urlsplit

from slice import _def_insn, _fqcn, _param_types, _reg, frame_of, guards_of_frame, method_key

RETROFIT = "Lretrofit2/http/"
KTORFIT = "Lde/jensklingenberg/ktorfit/http/"
HTTP_VERBS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
GSON_NAME = "Lcom/google/gson/annotations/SerializedName;"
GSON_FACTORY = "Lretrofit2/converter/gson/GsonConverterFactory;"
UNKNOWN = {"kind": "unknown"}


def annotation_values(cm, offset):
    if not offset:
        return {}
    annotation_set = cm.get_annotation_set_item(offset)
    if annotation_set is None:
        return {}
    result = {}
    for item in annotation_set.get_annotation_off_item():
        annotation = item.get_annotation_item().annotation
        result[cm.get_type(annotation.get_type_idx())] = {
            cm.get_string(element.get_name_idx()): element.get_value().get_value()
            for element in annotation.get_elements()
        }
    return result


@lru_cache(maxsize=None)
def annotations(owner):
    directory = owner.annotations_directory_item
    cm = owner.CM
    if directory is None:
        return {}, {}, {}
    methods = {a.get_method_idx(): annotation_values(cm, a.get_annotations_off())
               for a in directory.get_method_annotations()}
    fields = {a.get_field_idx(): annotation_values(cm, a.get_annotations_off())
              for a in directory.get_field_annotations()}
    params = {}
    for item in directory.get_parameter_annotations():
        refs = cm.get_obj_by_offset(item.get_annotations_off())
        params[item.get_method_idx()] = [annotation_values(cm, ref.get_annotations_off())
                                         for ref in refs.get_list()]
    return methods, fields, params


def dex_class(dx, descriptor):
    cls = dx.classes.get(descriptor)
    return cls.get_vm_class() if cls is not None and not cls.is_external() else None


@lru_cache(maxsize=None)
def annotated_routes(dx, cls, name):
    owner = dex_class(dx, cls)
    if owner is None:
        return []
    method_annotations, _, params = annotations(owner)
    routes = []
    for method in dx.classes[cls].get_methods():
        if method.name != name:
            continue
        idx = method.get_method().get_method_idx()
        for annotation, values in method_annotations.get(idx, {}).items():
            prefix = next((p for p in (RETROFIT, KTORFIT) if annotation.startswith(p)), "")
            if not prefix:
                continue
            verb = annotation[len(prefix):-1]
            target = values.get("value", "")
            has_body = verb in {"POST", "PUT", "PATCH"}
            if verb == "HTTP":
                verb, target = values.get("method", ""), values.get("path", "")
                has_body = bool(values.get("hasBody"))
            if verb not in HTTP_VERBS or not isinstance(target, str):
                continue
            body_args = [i for i, a in enumerate(params.get(idx, [])) if prefix + "Body;" in a]
            annotations_on_method = method_annotations[idx]
            routes.append({
                "method": method,
                "framework": "retrofit" if prefix == RETROFIT else "ktorfit",
                "verb": verb,
                "target": target,
                "body_argument": body_args[0] if len(body_args) == 1 else None,
                "body_mode": ("non_json" if any(prefix + kind in annotations_on_method
                                                for kind in ("FormUrlEncoded;", "Multipart;"))
                              else "json_candidate" if len(body_args) == 1
                              else "unknown" if has_body else "no_body"),
            })
    return routes


def normalized_route(target):
    parsed = urlsplit(target)
    return parsed.path.lstrip("/"), parsed.query


def bind_declaration(dx, row):
    cls = "L" + row["cls"].replace(".", "/") + ";"
    routes = annotated_routes(dx, cls, row["method"])
    path = normalized_route(row["path"])[0]
    matches = [r for r in routes if r["verb"] == row["verb"]
               and normalized_route(r["target"])[0] == path
               and (not normalized_route(r["target"])[1]
                    or normalized_route(r["target"])[1] == row["query"])]
    if len(matches) != 1:
        return {**row, "descriptor": None,
                "descriptor_candidates": sorted({r["method"].get_method().get_descriptor().replace(" ", "")
                                                 for r in matches})}
    route = matches[0]
    return {**row, "descriptor": route["method"].get_method().get_descriptor().replace(" ", ""),
            **{k: route[k] for k in ("framework", "body_argument", "body_mode")}}


def known_serializer(dx):
    """Recognize a default Gson Retrofit converter only with direct DEX evidence."""
    factory = dx.classes.get(GSON_FACTORY)
    if not factory:
        return None
    if any(name.startswith("Lretrofit2/converter/") and name.endswith("ConverterFactory;")
           and name != GSON_FACTORY for name in dx.classes):
        return None
    creates = [method for method in factory.get_methods() if method.name == "create"
               and method.get_xref_from()]
    if {m.get_method().get_descriptor().replace(" ", "") for m in creates} == {"()" + GSON_FACTORY}:
        return "gson"
    return None


@lru_cache(maxsize=None)
def raw_blocks(method):
    return {offset: instruction for offset, instruction in method.get_method().get_instructions_idx()}


def registers(instruction):
    return [r for operand in instruction.get_operands() if (r := _reg(operand)) is not None]


def arguments(regs, types):
    index = 0
    for typ in types:
        yield regs[index] if index < len(regs) else None
        index += 2 if typ in ("J", "D") else 1


def locate(fr, offset, method):
    block = fr["block_at"](offset)
    if block is None:
        return None
    raw = raw_blocks(method)
    cursor = fr["cfg"].nodes[block]["start"]
    for index in range(len(fr["cfg"].nodes[block]["insns"])):
        if cursor == offset:
            return block, index
        cursor += raw[cursor].get_length()
    return None


def guards_at(fr, block):
    guard_rows = []
    for guard in guards_of_frame(fr, fr["cfg"].nodes[block]["start"]):
        guard_rows.append({k: guard[k] for k in ("opcode", "sense", "operand")})
    return guard_rows


def value_from_register(method, fr, block, before, reg, depth=10, seen=frozenset()):
    if reg is None or depth <= 0 or (block, before, reg) in seen:
        return {"k": "unknown", "reason": "analysis_limit"}
    seen = seen | {(block, before, reg)}
    definition, reason, merge = _def_insn(fr["cfg"], block, before, reg)
    if definition is None:
        if reason != "merge":
            return {"k": "param" if reg in fr["params"] else "unknown", "reason": reason}
        choices = [
            (value_from_register(method, fr, pred, len(fr["cfg"].nodes[pred]["insns"]),
                                 reg, depth - 1, seen), pred)
            for pred in fr["cfg"].predecessors(merge)
        ]
        if choices and all(source == choices[0][0] for source, _ in choices):
            return choices[0][0]
        return {"k": "choice", "alternatives": [
            {"source": source, "guards": guards_at(fr, pred)} for source, pred in choices
        ]}

    src_block, index, insn = definition
    op = insn.op
    if op.startswith(("const-string", "const/4", "const/16", "const/high16", "const-wide")) or op == "const":
        return {"k": "const", "op": op, "value": insn.args[0]}
    if op.startswith("move") and not op.startswith(("move-result", "move-object", "move-exception")) and insn.args:
        return value_from_register(method, fr, src_block, index, insn.args[0], depth - 1, seen)
    if op == "new-instance" and src_block == block:
        return constructor_source(method, fr, block, index, before, reg, insn.args[0], depth, seen)
    kind = "field" if op.startswith(("iget", "sget")) else "invoke" if op.startswith("move-result") else "unknown"
    return {"k": kind, "reason": op, "detail": insn.args[0] if kind != "unknown" and insn.args else None}


def constructor_source(method, fr, block, first, before, reg, typ, depth, seen):
    raw = raw_blocks(method)
    cursor = fr["cfg"].nodes[block]["start"]
    constructor = None
    for index, insn in enumerate(fr["cfg"].nodes[block]["insns"][:before]):
        actual = raw[cursor]
        cursor += actual.get_length()
        if index <= first or reg not in registers(actual):
            continue
        signature = insn.args[0].replace(" ", "") if insn.args and isinstance(insn.args[0], str) else ""
        if (constructor is not None or not insn.op.startswith("invoke-direct")
                or not signature.startswith(f"{typ}-><init>(") or insn.args[1] != reg):
            return {"k": "unknown", "reason": "object_escapes_or_is_modified"}
        descriptor = signature.split("-><init>", 1)[1]
        arg_regs = arguments(insn.args[2:], _param_types(descriptor))
        constructor = {"k": "new", "type": typ, "descriptor": descriptor, "args": [
            value_from_register(method, fr, block, index, arg, depth - 1, seen) for arg in arg_regs
        ]}
    return constructor or {"k": "unknown", "reason": "constructor_not_found"}


def constructor_fields(owner, descriptor):
    """Only trust direct assignments from constructor arguments to this object's fields."""
    ctor = next((m for m in owner.get_methods() if m.get_name() == "<init>"
                 and m.get_descriptor().replace(" ", "") == descriptor), None)
    if ctor is None or ctor.get_code() is None or ctor.get_code().get_tries_size():
        return {}
    first_register = ctor.get_code().get_registers_size() - ctor.get_code().get_ins_size()
    receiver = f"v{first_register}"
    regs = [f"v{r}" for r in range(first_register + 1, ctor.get_code().get_registers_size())]
    params = {reg: i for i, reg in enumerate(arguments(regs, _param_types(descriptor)))}
    mapping = {}
    for instruction in ctor.get_instructions():
        op = instruction.get_name()
        operands = registers(instruction)
        ref = next((o[2] for o in instruction.get_operands() if len(o) == 3), "")
        if op.startswith("iput") and operands[1:] == [receiver] and ref.startswith(owner.get_name() + "->"):
            name = ref.split("->", 1)[1].split(" ", 1)[0]
            mapping[name] = params.get(operands[0])
        elif op.startswith("invoke-direct") and operands == [receiver] and ref == "Ljava/lang/Object;-><init>()V":
            continue
        elif op not in {"return-void", "nop"}:
            return {}
    return mapping


def model_for(dx, typ, source, *, depth=8):
    if depth == 0:
        return UNKNOWN
    if source.get("k") == "choice":
        choices = [model_for(dx, typ, entry["source"], depth=depth - 1)
                   for entry in source["alternatives"]]
        return choices[0] if choices and all(v == choices[0] for v in choices) else UNKNOWN
    if source.get("k") == "const":
        value = source["value"]
        op = source["op"]
        reference = typ.startswith(("L", "["))
        if typ == "Ljava/lang/String;" and op.startswith("const-string") and isinstance(value, str):
            return {"kind": "value", "value": value}
        if reference and value == 0:
            return {"kind": "value", "value": None}
        if typ in {"B", "S", "I", "J"} and type(value) is int:
            return {"kind": "value", "value": value}
        if typ == "Z" and value in (0, 1):
            return {"kind": "value", "value": bool(value)}
        return UNKNOWN
    owner = dex_class(dx, typ)
    if owner is None or owner.get_superclassname() != "Ljava/lang/Object;":
        return UNKNOWN
    if source.get("k") == "new" and source["type"] != typ:
        return UNKNOWN
    if owner.get_name().startswith(("Ljava/", "Lkotlin/", "Landroid/")) or owner.get_access_flags() & 0x4200:
        return UNKNOWN
    unsupported_prefixes = ("Lcom/squareup/moshi/", "Lcom/fasterxml/jackson/",
                            "Lkotlinx/serialization/", "Lcom/google/gson/annotations/JsonAdapter;")
    if any(a.startswith(unsupported_prefixes) for a in owner.get_annotations()):
        return UNKNOWN
    _, annotations_by_field, _ = annotations(owner)
    mapping = constructor_fields(owner, source["descriptor"]) if source.get("k") == "new" else {}
    field_models = {}
    for field in owner.get_fields():
        if field.get_access_flags() & (0x0008 | 0x0080 | 0x1000):
            continue
        metadata = annotations_by_field.get(field.get_field_idx(), {})
        if any(a.startswith(unsupported_prefixes) for a in metadata):
            return UNKNOWN
        name = metadata.get(GSON_NAME, {}).get("value", field.get_name())
        if not isinstance(name, str) or name in field_models:
            return UNKNOWN
        index = mapping.get(field.get_name())
        field_source = source["args"][index] if index is not None else UNKNOWN
        model = model_for(dx, field.get_descriptor(), field_source, depth=depth - 1) if index is not None else UNKNOWN
        # Gson's default object field policy excludes known nulls.
        if model == {"kind": "value", "value": None}:
            continue
        field_models[name] = model
    if not field_models and source.get("k") != "new":
        return UNKNOWN
    return {"kind": "object", "fields": field_models}


def expand_choices(source, budget=16):
    if source.get("k") == "choice" and 0 < len(source["alternatives"]) <= budget:
        expanded = []
        for alternative in source["alternatives"]:
            for value, guards in expand_choices(alternative["source"], budget):
                expanded.append((value, alternative["guards"] + guards))
                if len(expanded) > budget:
                    return [(source, [])]
        return expanded
    if source.get("k") == "new":
        args = source["args"]
        variants = [expand_choices(arg, budget) for arg in args]
        varying = [i for i, choices in enumerate(variants) if len(choices) > 1]
        # Several sibling phi nodes can describe the same branch. Avoid a
        # Cartesian product that would invent states impossible in the APK.
        if len(varying) == 1:
            i = varying[0]
            return [({**source, "args": args[:i] + [value] + args[i + 1:]}, guards)
                    for value, guards in variants[i]]
    return [(source, [])]


def unresolved_guards(source):
    if source.get("k") == "choice":
        return [g for option in source["alternatives"]
                for g in option["guards"] + unresolved_guards(option["source"])]
    return [g for arg in source.get("args", []) for g in unresolved_guards(arg)]


def declaration_method(dx, row):
    cls = "L" + row["cls"].replace(".", "/") + ";"
    owner = dx.classes.get(cls)
    return next((entry for entry in owner.get_methods()
                 if entry.name == row["method"] and entry.get_method().get_descriptor().replace(" ", "")
                 == row["descriptor"]), None) if owner else None


def request_slice(dx, row):
    from parameter_slice import layout, signature, trace_body

    method = declaration_method(dx, row)
    if method is None:
        return {"status": "dex_method_unavailable", "call_sites": []}
    sites = []
    types = _param_types(row["descriptor"])
    if types and types[-1] == "Lkotlin/coroutines/Continuation;":
        types.pop()
    refs = {(caller, offset) for _, caller, offset in method.get_xref_from() if not caller.is_external()}
    for caller, offset in sorted(refs, key=lambda pair: (signature(pair[0]), pair[1])):
        site = {"caller": signature(caller), "offset": offset, "arguments": []}
        sites.append(site)
        frame = layout(caller)
        if not frame or offset not in frame[3]:
            site["status"] = "unresolved_call_site"
            continue
        block, pos = frame[3][offset]
        invoke = frame[0].nodes[block]["insns"][pos]
        if not invoke.op.startswith("invoke") or (invoke.args[0] or "").replace(" ", "") != signature(method):
            site["status"] = "unresolved_call_site"
            continue
        regs = invoke.args[1:] if invoke.op.startswith("invoke-static") else invoke.args[2:]
        site["status"] = "analyzed"
        for index, (typ, reg) in enumerate(zip(types, arguments(regs, types))):
            arg = {"index": index, "type": typ}
            if reg is None:
                arg["status"] = "unresolved_register"
                site["status"] = "partial"
            else:
                arg["slice"] = trace_body(dx, caller, offset, reg)
                if arg["slice"]["limit_hit"]:
                    site["status"] = "partial"
            site["arguments"].append(arg)
    status = "analyzed" if sites else "no_direct_call_sites"
    if any(site["status"] != "analyzed" for site in sites):
        status = "partial"
    return {"status": status, "call_sites": sites}


def body_variants(dx, row, serializer):
    cls = "L" + row["cls"].replace(".", "/") + ";"
    method = declaration_method(dx, row)
    if method is None:
        return [{"status": "unsupported", "reason": "dex_method_unavailable", "call_sites": []}]
    references = sorted(set((caller, offset) for _, caller, offset in method.get_xref_from()
                            if not caller.is_external()),
                        key=lambda ref: (method_key(ref[0]), ref[0].get_method().get_descriptor(), ref[1]))
    sites = [{"caller": method_key(caller), "descriptor": caller.get_method().get_descriptor().replace(" ", ""),
              "offset": offset} for caller, offset in references]
    mode = row.get("body_mode")
    content_type = ((row.get("bfscan") or {}).get("content_type") or "").lower().split(";")[0].strip()
    if mode == "no_body":
        return [{"status": "no_body", "call_sites": sites}]
    if mode == "non_json" or content_type and content_type != "application/json" and not content_type.endswith("+json"):
        return [{"status": "non_json", "call_sites": sites}]
    if mode != "json_candidate":
        return [{"status": "unsupported", "reason": "body_argument_unresolved", "call_sites": sites}]
    if not sites:
        return [{"status": "unsupported", "reason": "no_direct_call_sites", "call_sites": []}]

    groups = {}
    sources = []
    types = _param_types(row["descriptor"])
    index = row["body_argument"]
    for (caller, offset), site in zip(references, sites):
        fr = frame_of(caller)
        location = locate(fr, offset, caller) if fr else None
        source = {"k": "unknown", "reason": "invoke_not_found"}
        parameter_slice = None
        if location and index < len(types):
            block, position = location
            insn = fr["cfg"].nodes[block]["insns"][position]
            expected = cls + "->" + row["method"] + row["descriptor"]
            if insn.op.startswith("invoke") and insn.args and insn.args[0].replace(" ", "") == expected:
                regs = insn.args[1:] if insn.op.startswith("invoke-static") else insn.args[2:]
                reg = list(arguments(regs, types))[index]
                source = value_from_register(caller, fr, block, position, reg)
                if types[index] == "Lokhttp3/RequestBody;" and reg is not None:
                    from parameter_slice import trace_body
                    parameter_slice = trace_body(dx, caller, offset, reg)
        sources.append((source, fr, location, site, parameter_slice))
    differing_sites = any(source != sources[0][0] for source, *_ in sources)
    for source, fr, location, site, parameter_slice in sources:
        site_guards = guards_at(fr, location[0]) if differing_sites and location else []
        for value, guards in expand_choices(source):
            variant = {"source": value, "guards": site_guards + guards}
            if parameter_slice is not None:
                variant["parameter_slice"] = parameter_slice
            if conditional := unresolved_guards(value):
                variant["unresolved_guards"] = conditional
            if index >= len(types):
                variant.update(status="unsupported", reason="body_argument_out_of_range")
            elif parameter_slice is not None:
                variant.update(status="partial", reason="raw_request_body")
            elif serializer == "gson":
                variant["model"] = model_for(dx, types[index], value)
            else:
                variant.update(status="unsupported", reason="serializer_unverified")
            group = groups.setdefault(json.dumps(variant, sort_keys=True), {**variant, "call_sites": []})
            group["call_sites"].append(site)
    return list(groups.values())

"""DEX binding and bounded data slicing for statically declared HTTP bodies."""

from collections import Counter
from functools import lru_cache
from urllib.parse import parse_qsl, urlsplit

from slice import _param_types, _reg

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
    example = Counter(parse_qsl(row["query"], keep_blank_values=True))
    matches = []
    for route in routes:
        route_path, fixed_query = normalized_route(route["target"])
        if route["verb"] == row["verb"] and route_path == path:
            fixed = Counter(parse_qsl(fixed_query, keep_blank_values=True))
            if fixed <= example:
                matches.append(route)
    if len(matches) != 1:
        return {**row, "descriptor": None,
                "descriptor_candidates": sorted({r["method"].get_method().get_descriptor().replace(" ", "")
                                                 for r in matches})}
    route = matches[0]
    return {**row, "descriptor": route["method"].get_method().get_descriptor().replace(" ", ""),
            **{k: route[k] for k in ("framework", "body_argument", "body_mode")}}




@lru_cache(maxsize=4096)
def raw_blocks(method):
    return {offset: instruction for offset, instruction in method.get_method().get_instructions_idx()}


def registers(instruction):
    return [r for operand in instruction.get_operands() if (r := _reg(operand)) is not None]


def arguments(regs, types):
    index = 0
    for typ in types:
        yield regs[index] if index < len(regs) else None
        index += 2 if typ in ("J", "D") else 1


















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

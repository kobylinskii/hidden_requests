"""Offline DEX operand provenance for Retrofit methods accepting an OkHttp RequestBody."""

from functools import lru_cache

from slice import _def_insn, _param_types, frame_of


def signature(method):
    return (
        method.class_name
        + "->"
        + method.name
        + method.get_method().get_descriptor().replace(" ", "")
    )


@lru_cache(maxsize=128)
def layout(method):
    from body_data import arguments, raw_blocks

    frame = frame_of(method)
    if frame is None:
        return None
    code = method.get_method().get_code()
    first = code.get_registers_size() - code.get_ins_size()
    types = _param_types(method.get_method().get_descriptor())
    instance = "static" not in method.get_access_flags_string().split()
    registers = [
        f"v{i}" for i in range(first + int(instance), code.get_registers_size())
    ]
    params = {
        reg: (idx, typ)
        for idx, (reg, typ) in enumerate(zip(arguments(registers, types), types))
    }
    if instance:
        params[f"v{first}"] = (-1, method.class_name)
    offsets = {}
    positions = {}
    raw = raw_blocks(method)
    for block, info in frame["cfg"].nodes(data=True):
        offset = info["start"]
        for pos, _ in enumerate(info["insns"]):
            offsets[block, pos] = offset
            positions[offset] = (block, pos)
            offset += raw[offset].get_length()
    return frame["cfg"], params, offsets, positions


def trace_body(dx, method, offset, register):
    from body_data import annotations, arguments, dex_class, raw_blocks, registers

    nodes = []
    visited = {}
    limit_hit = False

    def visit(ma, block, pos, reg):
        nonlocal limit_hit
        key = (ma, block, pos, reg)
        if key in visited:
            return visited[key]
        if len(nodes) >= 384 or len(active) >= 48:
            limit_hit = True
            return 0
        idx = len(nodes) + 1
        visited[key] = idx
        node = {"id": idx, "method": signature(ma)}
        nodes.append(node)
        active.add(idx)
        try:
            inspect(node, ma, block, pos, reg)
        finally:
            active.remove(idx)
        return idx

    def inspect(node, ma, block, pos, reg):
        cfg, params, offsets, _ = layout(ma)
        definition, reason, merge = _def_insn(cfg, block, pos, reg)
        if definition is None:
            if reason == "merge":
                node.update(
                    kind="alternatives",
                    inputs=[
                        visit(ma, p, len(cfg.nodes[p]["insns"]), reg)
                        for p in cfg.predecessors(merge)
                    ],
                )
            elif reason == "no_pred" and reg in params:
                index, typ = params[reg]
                node.update(
                    kind="receiver" if index < 0 else "parameter", index=index, type=typ
                )
            else:
                node.update(kind="unknown", reason=reason)
            return
        b, i, ins = definition
        off = offsets[b, i]
        node.update(offset=off, opcode=ins.op)
        raw = raw_blocks(ma)[off]
        op = ins.op
        if op.startswith("const"):
            node.update(kind="constant", value=ins.args[0])
        elif (
            op.startswith("move-result")
            and i
            and cfg.nodes[b]["insns"][i - 1].op.startswith("invoke")
        ):
            inv = cfg.nodes[b]["insns"][i - 1]
            node.update(
                kind="producer",
                target=inv.args[0],
                inputs=[visit(ma, b, i - 1, r) for r in inv.args[1:]],
            )
            # A static, zero-argument body factory has no caller bindings.
            # Walk each return separately so a JSON and a binary branch survive.
            target = inv.args[0]
            if inv.op.startswith("invoke-static") and target.endswith(
                "()Lokhttp3/RequestBody;"
            ):
                owner = target.partition("->")[0]
                candidates = (
                    dx.classes[owner].get_methods() if owner in dx.classes else []
                )
                callee = next(
                    (
                        m
                        for m in candidates
                        if not m.is_external() and signature(m) == target
                    ),
                    None,
                )
                if callee and layout(callee):
                    g, _, locs, _ = layout(callee)
                    node["returns"] = [
                        {
                            "offset": locs[k, j],
                            "source": visit(callee, k, j, use.args[0]),
                        }
                        for k, data in g.nodes(data=True)
                        for j, use in enumerate(data["insns"])
                        if use.op == "return-object" and use.args
                    ]
        elif (
            op.startswith("move")
            and ins.args
            and not op.startswith(("move-result", "move-exception"))
        ):
            node.update(kind="alias", inputs=[visit(ma, b, i, ins.args[0])])
        elif op.startswith(("iget", "sget")):
            field = ins.args[0]
            node.update(kind="field", field=field)
            owner, tail = field.split("->", 1)
            cls = dex_class(dx, owner)
            name, typ = tail.split(" ", 1)
            f = (
                next(
                    (
                        f
                        for f in cls.get_fields()
                        if f.get_name() == name and f.get_descriptor() == typ
                    ),
                    None,
                )
                if cls
                else None
            )
            regs = registers(raw)
            if (
                not op.startswith("iget")
                or not f
                or not f.get_access_flags() & 0x10
                or len(regs) != 2
            ):
                return
            receiver = visit(ma, b, i, regs[1])
            if (
                not receiver
                or nodes[receiver - 1].get("kind") != "receiver"
                or owner != ma.class_name
            ):
                return
            analysis = dx.get_field_analysis(f)
            writes = (
                sorted(
                    analysis.get_xref_write(with_offset=True),
                    key=lambda x: (signature(x[1]), x[2]),
                )
                if analysis
                else []
            )
            sites = []
            for _, ctor, at in writes:
                if ctor.name != "<init>" or ctor.class_name != owner:
                    return
                cfg2, params2, _, positions = layout(ctor)
                bb, p = positions[at]
                value, obj = registers(raw_blocks(ctor)[at])
                if (
                    params2.get(obj, (None, None))[0] != -1
                    or _def_insn(cfg2, bb, p, obj)[0] is not None
                ):
                    return
                source, why, _ = _def_insn(cfg2, bb, p, value)
                param = params2.get(value)
                if source or why != "no_pred" or not param or param[0] < 0:
                    return
                for _, caller, site in sorted(
                    ctor.get_xref_from(), key=lambda x: (signature(x[1]), x[2])
                ):
                    frame = layout(caller)
                    if not frame or site not in frame[3]:
                        continue
                    cb, cp = frame[3][site]
                    inv = frame[0].nodes[cb]["insns"][cp]
                    if not inv.op.startswith("invoke-direct") or inv.args[0].replace(
                        " ", ""
                    ) != signature(ctor):
                        continue
                    actual = list(
                        arguments(
                            inv.args[2:],
                            _param_types(ctor.get_method().get_descriptor()),
                        )
                    )[param[0]]
                    sites.append(
                        {
                            "constructor": signature(ctor),
                            "write_offset": at,
                            "argument": param[0],
                            "caller": signature(caller),
                            "offset": site,
                            "source": visit(caller, cb, cp, actual),
                        }
                    )
            if sites:
                node["possible_constructions"] = sites
        elif op == "new-instance":
            node.update(kind="allocation", type=ins.args[0])
            cls = dex_class(dx, ins.args[0])
            if cls:
                declared = []
                field_map = annotations(cls)[1]
                for f in cls.get_fields():
                    if f.get_access_flags() & 0x0008:
                        continue
                    metadata = field_map.get(f.get_field_idx(), {})
                    keys = {
                        tag: vals[key]
                        for tag, vals in metadata.items()
                        for key in ("jsonKey", "value")
                        if key in vals
                        and isinstance(vals[key], str)
                        and (
                            key == "jsonKey"
                            or tag == "Lcom/google/gson/annotations/SerializedName;"
                        )
                    }
                    declared.append(
                        {
                            "field": f.get_name(),
                            "type": f.get_descriptor(),
                            "name_annotations": keys,
                        }
                    )
                if declared:
                    node["declared_fields"] = declared
            # _def_insn only traverses single predecessors. Scan this same
            # reaching-definition segment for writes on the allocation register.
            segments = []
            end_block, end_pos = block, pos
            while end_block != b:
                segments.append((end_block, 0, end_pos))
                preds = list(cfg.predecessors(end_block))
                if len(preds) != 1:
                    break
                end_block = preds[0]
                end_pos = len(cfg.nodes[end_block]["insns"])
            segments.append((b, i + 1, end_pos))
            uses = []
            for segment, start, end in reversed(segments):
                for p in range(start, end):
                    use = cfg.nodes[segment]["insns"][p]
                    at = offsets[segment, p]
                    regs = registers(raw_blocks(ma)[at])
                    if use.op.startswith("iput") and regs[1:] == [reg]:
                        uses.append(
                            {
                                "field": use.args[0],
                                "offset": at,
                                "source": visit(ma, segment, p, regs[0]),
                            }
                        )
                    elif (
                        use.op.startswith("invoke")
                        and not use.op.startswith("invoke-static")
                        and use.args[1:2] == (reg,)
                    ):
                        uses.append(
                            {
                                "target": use.args[0],
                                "offset": at,
                                "inputs": [
                                    visit(ma, segment, p, r) for r in use.args[2:]
                                ],
                            }
                        )
            if uses:
                node["local_writes_and_calls"] = uses
        elif op == "new-array":
            node.update(kind="array", length=visit(ma, b, i, registers(raw)[1]))
        else:
            node.update(kind="unknown", reason=op)

    active = set()
    _, _, _, positions = layout(method)
    b, p = positions[offset]
    root = visit(method, b, p, register)
    if limit_hit:
        nodes.append({"id": 0, "kind": "unknown", "reason": "analysis_limit"})
    return {"root": root, "nodes": nodes, "limit_hit": limit_hit}

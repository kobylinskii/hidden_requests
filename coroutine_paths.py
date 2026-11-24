"""Find local structural links across Kotlin coroutine runtime boundaries."""
from functools import lru_cache

from body_data import dex_class
from parameter_slice import layout

_CONTINUATION = "Lkotlin/coroutines/Continuation;"
_CONTINUATION_IMPL = "Lkotlin/coroutines/jvm/internal/ContinuationImpl;"
_LAMBDA_BASES = {"Lkotlin/coroutines/jvm/internal/SuspendLambda;",
                 "Lkotlin/coroutines/jvm/internal/RestrictedSuspendLambda;"}
_INVOKE_SUSPEND = "(Ljava/lang/Object;)Ljava/lang/Object;"
_BUILDERS = {"Lkotlinx/coroutines/BuildersKt;", "Lkotlinx/coroutines/BuildersKt__Builders_commonKt;"}
_START = "Lkotlinx/coroutines/CoroutineStart;"
_BUILDER_PARAMS = ("Lkotlinx/coroutines/CoroutineScope;", "Lkotlin/coroutines/CoroutineContext;",
                   _START, "Lkotlin/jvm/functions/Function2;")
_BUILDER_RETURNS = {"launch": "Lkotlinx/coroutines/Job;", "async": "Lkotlinx/coroutines/Deferred;"}


def _receiver_parameter(cfg, params, block, pos, register):
    from slice import _def_insn

    for _ in range(12):
        definition, reason, _ = _def_insn(cfg, block, pos, register)
        if definition is None:
            return reason == "no_pred" and params.get(register, (None,))[0] == -1
        block, pos, ins = definition
        if not ins.op.startswith("move-object") or not ins.args:
            return False
        register = ins.args[0]
    return False


def _has_invoke_suspend_signature(method):
    return method.name == "invokeSuspend" and method.descriptor.replace(" ", "") == _INVOKE_SUSPEND


@lru_cache(maxsize=4096)
def resumed_method(dx, state, offset):
    """Resolve a compiler-generated re-entry call made with the current state object."""
    from slice import _cha_supers, _param_types

    if not _has_invoke_suspend_signature(state):
        return None
    ancestry = set(_cha_supers(dx, state.class_name))
    if _CONTINUATION_IMPL not in ancestry or ancestry & _LAMBDA_BASES:
        return None
    frame = layout(state)
    if frame is None or offset not in frame[3]:
        return None
    cfg, params, _, positions = frame
    block, pos = positions[offset]
    invoke = cfg.nodes[block]["insns"][pos]
    if not invoke.op.startswith(("invoke-static", "invoke-direct", "invoke-virtual")) or len(invoke.args) < 2:
        return None
    owner, _, member = (invoke.args[0] or "").partition("->")
    name, sep, descriptor = member.partition("(")
    descriptor = sep + descriptor
    if not descriptor.replace(" ", "").endswith(f"{_CONTINUATION})Ljava/lang/Object;"):
        return None
    if not _receiver_parameter(cfg, params, block, pos, invoke.args[-1]):
        return None
    owner_class = dx.classes.get(owner)
    if owner_class is None or owner_class.is_external():
        return None
    args = _param_types(descriptor)
    if not args or args[-1] != _CONTINUATION:
        return None
    target = next((m for m in owner_class.get_methods() if m.name == name
                   and m.descriptor.replace(" ", "") == descriptor.replace(" ", "")), None)
    if target is None:
        return None
    if invoke.op.startswith("invoke-virtual"):
        if "final" not in target.get_access_flags_string().split() and not (
                owner_class.get_vm_class().get_access_flags() & 0x10):
            return None
    # The same target constructs this continuation when entering from an ordinary call.
    state_class = dx.classes.get(state.class_name)
    if state_class and any(caller is target for caller, _ in state_class.get_xref_new_instance()):
        return target
    return None


def _eager_builder(cfg, block, pos, invoke):
    from slice import _def_insn, _integer_source

    if not invoke.op.startswith("invoke-static") or len(invoke.args) not in (5, 7):
        return False
    owner, _, member = (invoke.args[0] or "").replace(" ", "").partition("->")
    if owner not in _BUILDERS:
        return False
    name, sep, desc = member.partition("(")
    base = name.removesuffix("$default")
    if not sep or base not in _BUILDER_RETURNS:
        return False
    default = base != name
    extra = "ILjava/lang/Object;" if default else ""
    if desc != "".join(_BUILDER_PARAMS) + extra + ")" + _BUILDER_RETURNS[base]:
        return False
    if default:
        if len(invoke.args) != 7:
            return False
        kind, mask = _integer_source(cfg, block, pos, invoke.args[5])
        # The second defaultable argument is CoroutineStart; Function2 is required.
        if kind == "literal" and mask & 2:
            return True
    elif len(invoke.args) != 5:
        return False
    definition, _, _ = _def_insn(cfg, block, pos, invoke.args[3])
    return bool(definition and definition[2].op == "sget-object"
                and definition[2].args in {(_START + "->DEFAULT " + _START,),
                                           (_START + "->ATOMIC " + _START,),
                                           (_START + "->UNDISPATCHED " + _START,)})


@lru_cache(maxsize=4096)
def _local_launches(caller):
    """Group recognized eager launches by their local allocation instruction."""
    from slice import _allocation_origin

    frame = layout(caller)
    if frame is None:
        return {}
    cfg, _, offsets, _ = frame
    sites = {}
    for block, data in cfg.nodes(data=True):
        for pos, invoke in enumerate(data["insns"]):
            if not _eager_builder(cfg, block, pos, invoke):
                continue
            allocation = _allocation_origin(cfg, block, pos, invoke.args[4])
            if allocation is not None:
                sites.setdefault(allocation, []).append(offsets[block, pos])
    return sites


@lru_cache(maxsize=4096)
def launched_lambda_sites(dx, method, offset):
    """Find callers that schedule the same locally allocated suspend lambda."""
    from slice import _allocation_selector, _allocation_selector_value, _cha_supers

    if not _has_invoke_suspend_signature(method) or not _LAMBDA_BASES.intersection(
            _cha_supers(dx, method.class_name)):
        return (), False
    cls = dx.classes.get(method.class_name)
    if cls is None:
        return (), False
    allocations = cls.get_xref_new_instance()
    if not allocations:
        return (), False
    owner = dex_class(dx, method.class_name)
    selector = _allocation_selector(dx, method, offset)
    # A merged lambda can use a final int discriminator. If we cannot recover
    # its branch here, keep the old allocation-only evidence for the class.
    if selector is None and owner is not None and any(
            field.get_descriptor() == "I" and field.get_access_flags() & 0x10
            for field in owner.get_fields()):
        return (), False

    proven = set()
    unverified = False
    for caller, allocation_offset in allocations:
        if selector is not None:
            field, accepted = selector
            value = _allocation_selector_value(dx, caller, allocation_offset, field)
            if value is None:
                unverified = True
                continue
            if value not in accepted:
                continue
        frame = layout(caller)
        position = frame[3].get(allocation_offset) if frame else None
        matches = _local_launches(caller).get((*position, method.class_name), ()) if position else ()
        proven.update((caller, site) for site in matches)
        unverified |= not matches
    return tuple(proven), unverified

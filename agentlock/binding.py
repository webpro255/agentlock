"""Bind a call's arguments to parameter names before the gate sees them.

An adapter that hands the gate ``kwargs`` shows it only the part of the call
the caller happened to pass by keyword.  A positional argument and a parameter
default are just as much part of the call, and every parameter-level check the
gate performs is blind to them.  This module turns an ``(args, kwargs)`` pair
into the dict of what the call actually carries, keyed by parameter name.

Fail closed, twice.  A callable whose signature cannot be read cannot be bound,
and a wrapper that cannot bind cannot gate: :func:`ensure_bindable` is called
once at wrap time so the wrapper refuses to be built, rather than discovering
the problem on the first call with a caller waiting on the other end.  And a
call whose ``**kwargs`` mapping carries a key that names another parameter
cannot be flattened without one of the two values winning, so it is refused at
call time rather than resolved in the gate's favor or the function's.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from agentlock.exceptions import BindingError

__all__ = ["bind_call_parameters", "ensure_bindable"]


def ensure_bindable(func: Callable[..., Any]) -> inspect.Signature:
    """Return ``func``'s signature, or raise :class:`BindingError`.

    Args:
        func: The callable a wrapper is about to gate.

    Returns:
        The signature, so a caller that wants it need not read it twice.

    Raises:
        BindingError: ``inspect.signature`` refused the callable.  Builtins
            without a text signature and objects that raise when asked to
            describe themselves both land here.
    """
    try:
        return inspect.signature(func)
    except (ValueError, TypeError) as exc:
        raise BindingError(
            f"Cannot read the signature of {func!r}, so its arguments cannot "
            f"be bound and its calls cannot be gated: {exc}"
        ) from exc


def _reject_shadowing_keys(
    func: Callable[..., Any],
    signature: inspect.Signature,
    var_keyword_name: str,
    mapping: Mapping[str, Any],
) -> None:
    """Refuse a ``**kwargs`` mapping whose keys shadow a real parameter.

    Flattening a ``VAR_KEYWORD`` mapping onto the top-level parameters dict
    puts its keys where a caller passing them by keyword would have put them.
    That is the right view for every key the signature has no parameter for.
    For a key that names another parameter it is not: the parameter has a
    value of its own, the mapping has a different one, and whichever the
    flattening writes last is what the gate is shown while the function runs
    with the other.  ``def send(to, /, **extras)`` called as
    ``send(hostile, to=contact)`` is the shape: ``to`` is positional only, so
    ``to=contact`` is an entry of ``extras`` and never reaches the parameter.

    A key equal to ``var_keyword_name`` itself is not a collision.  There is
    no parameter of that name for it to shadow, so the gate and the function
    see the same mapping and the call is bound normally.

    Args:
        func: The callable being gated, named in the error.
        signature: Its signature.
        var_keyword_name: Name of the ``VAR_KEYWORD`` parameter being
            flattened, which is excluded from the shadowable set.
        mapping: The mapping's contents.

    Raises:
        BindingError: At least one key names another parameter.
    """
    shadowable = {
        name for name in signature.parameters if name != var_keyword_name
    }
    shadowed = sorted(key for key in mapping if key in shadowable)
    if not shadowed:
        return

    name = getattr(func, "__name__", None) or repr(func)
    keys = ", ".join(repr(key) for key in shadowed)
    raise BindingError(
        f"Cannot bind a call to {name}: {keys} arrived in its "
        f"**{var_keyword_name} mapping and also names one of its parameters. "
        f"Flattening the mapping would show the gate a value the function "
        f"does not receive under that name, so the call is refused before it "
        f"is authorized."
    )


def bind_call_parameters(
    func: Callable[..., Any],
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
) -> tuple[dict[str, Any], inspect.BoundArguments]:
    """Bind a call to ``func``'s parameters and return what it carries.

    Defaults are applied, so a parameter the caller omitted is present with
    the value the call will actually run with.  Variadics keep their shape: a
    ``**kwargs`` parameter's contents are flattened to the top level, because
    that is where a caller passing them by keyword would have put them, and a
    ``*args`` parameter is kept as a tuple under its own name, because its
    entries have no names to be keyed by.

    A ``**kwargs`` key that names another parameter is refused rather than
    flattened over it: see :func:`_reject_shadowing_keys`.  A key equal to the
    ``**kwargs`` parameter's own name is not such a key and is bound normally.

    Args:
        func: The callable being gated.
        args: Positional arguments of the call.
        kwargs: Keyword arguments of the call, with any reserved
            authorization kwargs already removed by the caller.

    Returns:
        ``(parameters, bound)``.  ``parameters`` is what the gate is shown.
        ``bound`` reconstructs the call: invoke ``func(*bound.args,
        **bound.kwargs)``.

    Raises:
        BindingError: The signature cannot be read, or a ``**kwargs`` key
            names another parameter of the same callable.  The second is a
            call-time refusal and reaches the caller: the call is not
            authorized and is not made.
        TypeError: The arguments do not fit the signature.  Raised by
            ``bind_partial`` and left unchanged, because a call that cannot be
            made is the caller's error and not an authorization decision.
    """
    signature = ensure_bindable(func)
    bound = signature.bind_partial(*args, **kwargs)
    bound.apply_defaults()

    parameters: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        if name not in bound.arguments:
            continue
        value = bound.arguments[name]
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            _reject_shadowing_keys(func, signature, name, value)
            parameters.update(value)
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            parameters[name] = tuple(value)
        else:
            parameters[name] = value
    return parameters, bound

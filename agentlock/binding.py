"""Bind a call's arguments to parameter names before the gate sees them.

An adapter that hands the gate ``kwargs`` shows it only the part of the call
the caller happened to pass by keyword.  A positional argument and a parameter
default are just as much part of the call, and every parameter-level check the
gate performs is blind to them.  This module turns an ``(args, kwargs)`` pair
into the dict of what the call actually carries, keyed by parameter name.

A :class:`functools.partial` is part of the call too.  Its signature describes
the call still to be made, not the function that will run, so the arguments it
already carries are absent from it.  Every entry point here collapses a chain
of partials into the call it stands for and works on the callable underneath.

Fail closed, four times.  A callable whose signature cannot be read cannot be
bound, and a wrapper that cannot bind cannot gate, so :func:`ensure_bindable`
refuses at wrap time rather than on the first call with a caller waiting.  A
permission block that declares a recipient parameter no signature can carry is
refused at the same moment, because a declaration that can never be read is
worse than none.  A call whose ``**kwargs`` mapping carries a key that names
another parameter cannot be flattened without one of the two values winning,
and a call that puts its recipient in an unnamed positional argument cannot be
checked against recipient policy at all: both are refused at call time, before
the gate is asked anything.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from agentlock.exceptions import BindingError

__all__ = [
    "apply_effective_parameters",
    "bind_call_parameters",
    "ensure_bindable",
    "unwrap_partial",
]


def unwrap_partial(func: Callable[..., Any]) -> Callable[..., Any]:
    """Return the callable a chain of partials ultimately calls.

    A wrapper invokes what :func:`bind_call_parameters` bound, and what it
    bound is this callable, not the partial that stands in front of it.
    Calling the partial with a binding taken from the function underneath
    would apply the partial's own arguments a second time.

    Args:
        func: Any callable.  A callable that is not a partial is returned
            unchanged, which is the common case.

    Returns:
        The innermost callable.
    """
    target: Any = func
    while isinstance(target, functools.partial | functools.partialmethod):
        target = target.func
    return target  # type: ignore[no-any-return]


def _collapse_partial_call(
    func: Callable[..., Any],
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
) -> tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]:
    """Rewrite ``func(*args, **kwargs)`` as the call it actually makes.

    Layers are peeled outermost first.  Each layer's positional arguments go
    in front of everything already accumulated, because that is where the
    partial puts them, and its keywords go underneath, because a keyword
    supplied at the call site wins over one the partial carries.  Nested
    partials fall out of the loop in the right order without a special case.

    Args:
        func: The callable a wrapper was handed.
        args: Positional arguments of the call.
        kwargs: Keyword arguments of the call.

    Returns:
        ``(target, args, kwargs)`` for the equivalent direct call.
    """
    target: Any = func
    call_args = tuple(args)
    call_kwargs = dict(kwargs)
    while isinstance(target, functools.partial | functools.partialmethod):
        call_args = tuple(target.args) + call_args
        call_kwargs = {**target.keywords, **call_kwargs}
        target = target.func
    return target, call_args, call_kwargs


def _callable_name(func: Callable[..., Any]) -> str:
    """A name for ``func`` to put in an error message."""
    return getattr(func, "__name__", None) or repr(func)


def ensure_bindable(
    func: Callable[..., Any],
    *,
    must_observe: str | None = None,
) -> inspect.Signature:
    """Return ``func``'s signature, or raise :class:`BindingError`.

    The signature returned is that of the callable underneath any partials,
    which is the one a call is bound against.

    Args:
        func: The callable a wrapper is about to gate.
        must_observe: Name of a parameter the permission block declares and
            the gate must be able to read, normally
            ``scope.recipient_parameter``.  ``None`` when the block declares
            none, which is the common case and checks nothing.

    Returns:
        The signature, so a caller that wants it need not read it twice.

    Raises:
        BindingError: ``inspect.signature`` refused the callable.  Builtins
            without a text signature and objects that raise when asked to
            describe themselves both land here.  Or ``must_observe`` names a
            parameter this callable has no way to receive.
    """
    target = unwrap_partial(func)
    try:
        signature = inspect.signature(target)
    except (ValueError, TypeError) as exc:
        raise BindingError(
            f"Cannot read the signature of {target!r}, so its arguments cannot "
            f"be bound and its calls cannot be gated: {exc}"
        ) from exc

    if must_observe is not None:
        _require_observable(target, signature, must_observe)
    return signature


def _require_observable(
    func: Callable[..., Any],
    signature: inspect.Signature,
    must_observe: str,
) -> None:
    """Refuse a declared parameter this signature can never carry.

    A permission block that names a recipient parameter is read at pipeline
    step 8 by looking that name up in the bound parameters.  A signature with
    no parameter of that name and no ``**kwargs`` for one to arrive in can
    never produce that key, so the declaration is unenforceable over this
    callable no matter what any caller does.  Silent unenforceability is the
    shape a permission block exists to prevent, so the pair is refused where
    it is made.

    Args:
        func: The callable being gated, named in the error.
        signature: Its signature, already read.
        must_observe: The declared parameter name.

    Raises:
        BindingError: The signature can never carry that name.
    """
    if must_observe in signature.parameters:
        return
    if any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        return

    raise BindingError(
        f"Cannot gate {_callable_name(func)} with this permission block: it "
        f"declares scope.recipient_parameter={must_observe!r} and the "
        f"signature {signature} has no parameter of that name and no "
        f"**kwargs one could arrive in. The declared recipient parameter "
        f"cannot be observed on this callable, so recipient policy would "
        f"never be enforced over it. Give the function a {must_observe} "
        f"parameter, or stop declaring one."
    )


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

    A partial reaches this rule the same way, because its own arguments are
    collapsed into the call before the binding runs.
    ``partial(send, hostile)`` called with ``to=contact`` is the shape above
    with the hostile address supplied a step earlier.

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

    keys = ", ".join(repr(key) for key in shadowed)
    raise BindingError(
        f"Cannot bind a call to {_callable_name(func)}: {keys} arrived in its "
        f"**{var_keyword_name} mapping and also names one of its parameters. "
        f"Flattening the mapping would show the gate a value the function "
        f"does not receive under that name, so the call is refused before it "
        f"is authorized."
    )


def _reject_unnameable_positionals(
    func: Callable[..., Any],
    signature: inspect.Signature,
    parameters: Mapping[str, Any],
    must_observe: str,
) -> None:
    """Refuse a call that hides a declared parameter in ``*args``.

    ``def send(*args, **kw)`` can carry a ``to``, so
    :func:`_require_observable` lets the pair be built.  A particular call may
    still put the recipient where it has no name: ``send(hostile)`` binds
    ``args=(hostile,)`` and no ``to`` at all, pipeline step 8 finds nothing to
    read, and the declared policy decides nothing.  The gate does not guess
    which unnamed positional was meant to be the recipient, so the call is
    refused.

    A call with no positional extras is not this case.  The declared
    parameter is simply absent, which is the skip the gate already has and
    which this function leaves alone.

    Args:
        func: The callable being gated, named in the error.
        signature: Its signature.
        parameters: What the binding produced.
        must_observe: The declared parameter name.

    Raises:
        BindingError: The call carries positional arguments the gate cannot
            name while a recipient parameter is declared.
    """
    carried = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind is inspect.Parameter.VAR_POSITIONAL
        and parameters.get(name)
    ]
    if not carried:
        return

    var_positional = carried[0]
    count = len(parameters[var_positional])
    raise BindingError(
        f"Cannot bind a call to {_callable_name(func)}: its permission block "
        f"declares scope.recipient_parameter={must_observe!r}, the call "
        f"carries no argument of that name, and {count} argument(s) arrived "
        f"in *{var_positional}, where the gate cannot name them. Recipient "
        f"policy cannot be enforced against an argument that has no name, so "
        f"the call is refused before it is authorized. Pass the recipient as "
        f"{must_observe}=..."
    )


def apply_effective_parameters(
    bound: inspect.BoundArguments,
    effective: Mapping[str, Any],
) -> inspect.BoundArguments:
    """Write authorized parameter values back into a bound call.

    :func:`bind_call_parameters` flattens a call into the name keyed view the
    gate reasons about.  When the gate transforms one of those values, the
    transformed value has to travel back the other way, into the binding the
    function is actually invoked from, or the tool runs with the untransformed
    argument and the transformation was decoration.  This is that return trip,
    and it is the inverse of the flattening, name for name:

    * a normal parameter, positional only included, is overwritten by name;
      ``BoundArguments.args`` rebuilds the positional call from
      ``arguments``, so writing by name reaches an argument that has no
      keyword form;
    * a ``*args`` parameter is kept under its own name as a tuple by the
      flattening and is restored as a tuple here;
    * a ``**kwargs`` mapping was flattened to the top level, so each key it
      carried is taken back out of the top level and put back in the mapping.
      Keys the flattening never produced are left alone, because a
      transformation cannot invent a parameter.

    A parameter absent from ``bound.arguments`` is left absent: the binding
    describes a call that was already made, and this function changes values
    in it, never its shape.

    Args:
        bound: The binding to update, mutated in place.
        effective: The gate's authorized parameters, in the flattened view.

    Returns:
        The same ``bound``, for convenience at a call site.
    """
    for name, parameter in bound.signature.parameters.items():
        if name not in bound.arguments:
            continue
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            mapping = bound.arguments[name]
            bound.arguments[name] = {
                key: effective.get(key, value)
                for key, value in mapping.items()
            }
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            if name in effective:
                bound.arguments[name] = tuple(effective[name])
        elif name in effective:
            bound.arguments[name] = effective[name]
    return bound


def bind_call_parameters(
    func: Callable[..., Any],
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    *,
    must_observe: str | None = None,
) -> tuple[dict[str, Any], inspect.BoundArguments]:
    """Bind a call to ``func``'s parameters and return what it carries.

    Defaults are applied, so a parameter the caller omitted is present with
    the value the call will actually run with.  Variadics keep their shape: a
    ``**kwargs`` parameter's contents are flattened to the top level, because
    that is where a caller passing them by keyword would have put them, and a
    ``*args`` parameter is kept as a tuple under its own name, because its
    entries have no names to be keyed by.

    Partials are collapsed first, so the arguments a partial already carries
    are part of what the gate is shown rather than invisible to it.  The
    binding returned is against the callable underneath: invoke it as
    ``unwrap_partial(func)(*bound.args, **bound.kwargs)``.

    A ``**kwargs`` key that names another parameter is refused rather than
    flattened over it: see :func:`_reject_shadowing_keys`.  A key equal to the
    ``**kwargs`` parameter's own name is not such a key and is bound normally.

    Args:
        func: The callable being gated.
        args: Positional arguments of the call.
        kwargs: Keyword arguments of the call, with any reserved
            authorization kwargs already removed by the caller.
        must_observe: Name of a parameter the permission block declares and
            the gate must be able to read, normally
            ``scope.recipient_parameter``.  ``None`` checks nothing.

    Returns:
        ``(parameters, bound)``.  ``parameters`` is what the gate is shown.
        ``bound`` reconstructs the call against the callable underneath any
        partials.

    Raises:
        BindingError: The signature cannot be read; or a ``**kwargs`` key
            names another parameter of the same callable; or ``must_observe``
            is absent from the bound parameters while unnamed positional
            arguments were supplied.  The last two are call-time refusals and
            reach the caller: the call is not authorized and is not made.
        TypeError: The arguments do not fit the signature.  Raised by
            ``bind_partial`` and left unchanged, because a call that cannot be
            made is the caller's error and not an authorization decision.
    """
    target, call_args, call_kwargs = _collapse_partial_call(func, args, kwargs)
    signature = ensure_bindable(target)
    bound = signature.bind_partial(*call_args, **call_kwargs)
    bound.apply_defaults()

    parameters: dict[str, Any] = {}
    for name, parameter in signature.parameters.items():
        if name not in bound.arguments:
            continue
        value = bound.arguments[name]
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            _reject_shadowing_keys(target, signature, name, value)
            parameters.update(value)
        elif parameter.kind is inspect.Parameter.VAR_POSITIONAL:
            parameters[name] = tuple(value)
        else:
            parameters[name] = value

    if must_observe is not None and must_observe not in parameters:
        _reject_unnameable_positionals(
            target, signature, parameters, must_observe
        )
    return parameters, bound

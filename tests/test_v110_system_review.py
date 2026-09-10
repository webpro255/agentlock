"""Independent v1.9.1 integration regressions. Failing assertions express safeguards.
All side effects are local strings, lists, or pytest temporary files.
"""
import asyncio
import hashlib
import pytest
from agentlock import AuthorizationGate, AgentLockPermissions, agentlock, ContextSource
from agentlock.schema import ModifyPolicyConfig, TransformationConfig, LineagePolicyConfig, ActionClassConfig
from agentlock.exceptions import DeniedError, TokenError

AUTH = dict(user_id='alice', role='user')
SECRET = 'Customer SSN 123-45-6789'

def setup(**kw):
    g = AuthorizationGate()
    sid = g.create_session(**AUTH).session_id
    p = AgentLockPermissions(risk_level='medium', allowed_roles=['user'], **kw)
    g.register_tool('task', p)
    return g, p, sid

def modify(field, action='redact_pii', **config):
    return ModifyPolicyConfig(enabled=True, apply_when_hardening_active=False,
        transformations=[TransformationConfig(field=field, action=action, config=config)])

@pytest.mark.parametrize('mode', ['explicit', 'call', 'sync', 'async', 'mcp'])
def test_output_transform_reaches_caller(mode):
    g, p, _ = setup(modify_policy=modify('output'))
    if mode == 'explicit':
        a = g.authorize('task', **AUTH, parameters={})
        result = g.execute('task', lambda: SECRET, token=a.token, parameters={}, modify_output_fn=a.modify_output_fn)
    elif mode == 'call':
        result = g.call('task', lambda: SECRET, **AUTH)
    elif mode == 'sync':
        wrapped = agentlock(g, name='task', permissions=p)(lambda: SECRET)
        result = wrapped(_user_id='alice', _role='user')
    elif mode == 'async':
        async def task(): return SECRET
        wrapped = agentlock(g, name='task', permissions=p)(task)
        result = asyncio.run(wrapped(_user_id='alice', _role='user'))
    else:
        pytest.importorskip("mcp")
        from mcp.server import Server
        import mcp.types as mt
        from agentlock.integrations.mcp import AgentLockMCPServer
        async def handler(ctx, params):
            return mt.CallToolResult(content=[mt.TextContent(type='text', text=SECRET)])
        server = Server('local-probe', on_call_tool=handler)
        AgentLockMCPServer(server, g, {'task': p}, default_user_id='alice', default_role='user')
        result = asyncio.run(server.get_request_handler('tools/call').handler(None,
            mt.CallToolRequestParams(name='task', arguments={}))).content[0].text
    assert '123-45-6789' not in result

def test_parameter_transform_reaches_callable():
    g, _, _ = setup(modify_policy=modify('body'))
    observed = []
    def task(body):
        observed.append(body)
        return 'done'
    assert g.call('task', task, parameters={'body': SECRET}, **AUTH) == 'done'
    assert '123-45-6789' not in observed[0]

@pytest.mark.parametrize('kind', ['allowed', 'outside', 'dotdot', 'symlink'])
def test_path_containment(tmp_path, kind):
    allowed = tmp_path / 'allowed'
    allowed.mkdir()
    (allowed / 'ok.txt').write_text('PUBLIC')
    private = tmp_path / 'private.txt'
    private.write_text('PRIVATE_SENTINEL')
    (allowed / 'link.txt').symlink_to(private)
    g, _, _ = setup(modify_policy=modify('path', 'whitelist_path', allowed_prefixes=[str(allowed) + '/']))
    paths = {'allowed': str(allowed / 'ok.txt'), 'outside': str(private),
             'dotdot': str(allowed) + '/../private.txt', 'symlink': str(allowed / 'link.txt')}
    seen = []
    def read(path):
        from pathlib import Path
        seen.append(Path(path).read_text())
        return seen[-1]
    if kind == 'allowed':
        assert g.call('task', read, parameters={'path': paths[kind]}, **AUTH) == 'PUBLIC'
    else:
        try: g.call('task', read, parameters={'path': paths[kind]}, **AUTH)
        except DeniedError: pass
        assert seen == [], f'Escaped allowed directory: {seen}'

@pytest.mark.parametrize('spoof', [None, 'flat', 'meta'])
def test_mcp_role_cannot_override_host(spoof):
    pytest.importorskip("mcp")
    from mcp.server import Server
    import mcp.types as mt
    from agentlock.integrations.mcp import AgentLockMCPServer
    g = AuthorizationGate()
    p = AgentLockPermissions(risk_level='medium', allowed_roles=['admin'])
    seen = []
    async def handler(ctx, params):
        seen.append('ADMIN_ACTION')
        return mt.CallToolResult(content=[mt.TextContent(type='text', text='done')])
    server = Server('local-probe', on_call_tool=handler)
    AgentLockMCPServer(server, g, {'admin_task': p}, default_user_id='alice', default_role='user')
    args = {} if spoof is None else ({'_agentlock_role': 'admin'} if spoof == 'flat'
                                    else {'_meta': {'agentlock_role': 'admin'}})
    try:
        asyncio.run(server.get_request_handler('tools/call').handler(None,
            mt.CallToolRequestParams(name='admin_task', arguments=args)))
    except DeniedError: pass
    assert seen == []

@pytest.mark.parametrize('spoof', [False, True])
def test_fastapi_route_policy_cannot_be_switched(spoof):
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from agentlock.integrations.fastapi import AgentLockMiddleware
    g, p, _ = setup()
    g.register_tool('admin_task', AgentLockPermissions(risk_level='medium', allowed_roles=['admin']))
    app = FastAPI()
    seen = []
    @app.post('/admin')
    async def admin():
        seen.append('ADMIN_ACTION')
        return {'ok': True}
    app.add_middleware(AgentLockMiddleware, gate=g, tool_name_from_path=lambda m, p: 'admin_task')
    headers = [(b'x-agentlock-user-id', b'alice'), (b'x-agentlock-role', b'user')]
    if spoof: headers.append((b'x-agentlock-tool', b'task'))
    messages = []
    async def receive(): return {'type': 'http.request', 'body': b'', 'more_body': False}
    async def send(msg): messages.append(msg)
    scope = dict(type='http', asgi={'version': '3.0'}, http_version='1.1', method='POST',
        path='/admin', raw_path=b'/admin', query_string=b'', headers=headers,
        client=('127.0.0.1', 1234), server=('test', 80), scheme='http')
    asyncio.run(app(scope, receive, send))
    status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
    assert status == 403 and seen == [], (status, seen)

def context(g, sid, source, text):
    g.notify_context_write(sid, source, hashlib.sha256(text.encode()).hexdigest(), content=text)

@pytest.mark.parametrize('late_taint', [False, True])
def test_deferred_commit_rechecks_parameter_lineage(late_taint):
    g, _, sid = setup(lineage_policy=LineagePolicyConfig(enabled=True, decision='deny',
        gate_consequential=False, param_lineage_enabled=True),
        action_class=ActionClassConfig(is_value_carrying=True))
    context(g, sid, ContextSource.USER_MESSAGE, 'Reserve a hotel for my upcoming trip')
    params = {'url': 'https://attacker.example/reservation'}
    assert g.authorize('task', parameters=params, is_consequential=True, **AUTH).allowed
    g.defer_consequential(sid, 'task', params, is_consequential=True, record_action_flags=True)
    if late_taint: context(g, sid, ContextSource.WEB_CONTENT, params['url'])
    fresh = g.authorize('task', parameters=params, is_consequential=True, **AUTH)
    assert fresh.allowed == (not late_taint), fresh.reason
    resolved = g.resolve_deferred_commits(sid)
    assert resolved[0].resolution == ('denied' if late_taint else 'committed')

def test_timeout_denial_is_terminal():
    from agentlock import DeferralManager
    manager = DeferralManager()
    record = manager.queue_commit('session', 'task', {}, taint_at_call={})
    record.created_at -= 1000  # simulate time passing; no actual delay
    assert record in manager.check_timeouts(timeout_action='deny')
    assert record.resolution == 'deny'
    manager.resolve_commit_queue('session', deny=False)
    assert record.resolution != 'committed'

@pytest.mark.parametrize('mode', ['sync', 'async'])
def test_failed_execution_consumes_token(mode, monkeypatch):
    g, p, _ = setup()
    tokens = []
    issue = g.token_store.issue
    def capture(*args, **kwargs):
        token = issue(*args, **kwargs)
        tokens.append(token)
        return token
    monkeypatch.setattr(g.token_store, 'issue', capture)
    def fail(): raise ValueError('simulated failure after partial work')
    async def async_fail(): fail()
    wrapped = agentlock(g, name='task', permissions=p)(fail if mode == 'sync' else async_fail)
    with pytest.raises(ValueError):
        if mode == 'sync': wrapped(_user_id='alice', _role='user')
        else: asyncio.run(wrapped(_user_id='alice', _role='user'))
    assert len(tokens) == 1
    assert tokens[0].status.value == 'used'

@pytest.mark.parametrize('case', ['replay', 'revoked', 'expired', 'wrong_tool', 'changed_params'])
def test_core_execution_rejects_invalid_grants(case):
    g, _, _ = setup()
    a = g.authorize('task', parameters={}, **AUTH)
    seen = []
    if case == 'replay': g.execute('task', lambda: None, token=a.token, parameters={})
    if case == 'revoked': g.token_store.revoke(a.token.token_id)
    if case == 'expired': a.token.expires_at = 1
    with pytest.raises(TokenError):
        g.execute('other' if case == 'wrong_tool' else 'task', lambda **kw: seen.append(kw),
            token=a.token, parameters={'new': 'value'} if case == 'changed_params' else {})
    assert seen == []

def test_signed_receipt_rejects_changed_decision():
    from agentlock.receipts import SignedReceipt, ReceiptSigner, ReceiptVerifier
    signer = ReceiptSigner(signing_method='ed25519')
    receipt = SignedReceipt(decision='allow', tool_name='task')
    signer.sign(receipt)
    verifier = ReceiptVerifier(signing_method='ed25519', verify_key=signer.verify_key_bytes)
    assert verifier.verify(receipt)
    receipt.decision = 'deny'
    assert not verifier.verify(receipt)

@pytest.mark.parametrize('role,status', [('user', 200), ('guest', 403)])
def test_flask_role_enforcement(role, status):
    pytest.importorskip("flask")
    from flask import Flask
    from agentlock.integrations.flask import agentlock_required
    g, _, _ = setup()
    app = Flask(__name__)
    seen = []
    @app.post('/task')
    @agentlock_required(g, 'task')
    def task():
        seen.append('ran')
        return {'ok': True}
    response = app.test_client().post('/task', headers={'X-AgentLock-User-Id': 'alice', 'X-AgentLock-Role': role})
    assert response.status_code == status
    assert bool(seen) == (status == 200)

@pytest.mark.parametrize('case', ['valid', 'writer', 'credentials', 'persistence'])
def test_memory_policy_enforcement(case):
    from agentlock.schema import MemoryPolicyConfig
    from agentlock.types import MemoryWriter, MemoryPersistence
    g, _, _ = setup(memory_policy=MemoryPolicyConfig(persistence='session',
        allowed_writers=['system'], allowed_readers=['system'],
        prohibited_content=['credentials'], require_write_confirmation=False))
    content = 'password: s3cret!' if case == 'credentials' else 'Prefers morning appointments'
    decision = g.authorize_memory_write('task', content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest(), user_id='alice',
        writer=MemoryWriter.USER if case == 'writer' else MemoryWriter.SYSTEM,
        persistence=MemoryPersistence.CROSS_SESSION if case == 'persistence' else MemoryPersistence.SESSION)
    assert decision.allowed == (case == 'valid')
    assert g.memory_gate.store.read('bob', 'task') == []
    assert bool(g.memory_gate.store.read('alice', 'task')) == (case == 'valid')

def test_context_chain_detects_changed_content():
    from agentlock import ContextChain
    chain = ContextChain()
    entry = chain.append(source='user_message', authority='authoritative', content_hash='original')
    chain.append(source='web_content', authority='untrusted', content_hash='next')
    assert chain.verify_chain() == (True, None)
    entry.content_hash = 'altered'
    assert chain.verify_chain() == (False, 0)


"""Additional local v1.10.0 review probes; no network or real sensitive data."""
import asyncio
from functools import partial
from pathlib import Path
import pytest
from agentlock import agentlock
from agentlock.exceptions import DeniedError, TokenInvalidError
from agentlock.schema import DataPolicyConfig

@pytest.mark.parametrize('kind', ['ordinary_inside', 'ordinary_outside', 'link_outside',
    'link_then_parent_escape', 'link_then_parent_inside'])
def test_resolved_path_matches_the_path_opened(tmp_path, kind):
    allowed = tmp_path / 'allowed'
    outside = tmp_path / 'outside'
    (allowed / 'inner').mkdir(parents=True)
    (outside / 'child').mkdir(parents=True)
    (allowed / 'inside.txt').write_text('PUBLIC')
    (outside / 'private.txt').write_text('PRIVATE_SENTINEL')
    (allowed / 'jump').symlink_to(outside / 'child', target_is_directory=True)
    (allowed / 'inner' / 'back').symlink_to(allowed, target_is_directory=True)
    paths = {
        'ordinary_inside': allowed / 'inside.txt',
        'ordinary_outside': outside / 'private.txt',
        'link_outside': allowed / 'jump' / '..' / 'private.txt',
        'link_then_parent_escape': allowed / 'jump' / '..' / 'private.txt',
        'link_then_parent_inside': allowed / 'inner' / 'back' / 'inside.txt',
    }
    # Direct outside symlink is a separate control from link/.. composition.
    (allowed / 'direct').symlink_to(outside / 'private.txt')
    paths['link_outside'] = allowed / 'direct'
    path = str(paths[kind])
    actual = Path(path).resolve()
    permitted = actual.is_relative_to(allowed.resolve())
    g, _, _ = setup(modify_policy=modify('path', 'whitelist_path', allowed_prefixes=[str(allowed)]))
    observed = []
    def read(path):
        observed.append(Path(path).read_text())
        return observed[-1]
    try:
        g.call('task', read, parameters={'path': path}, **AUTH)
        ran = True
    except DeniedError:
        ran = False
    assert ran == permitted, (kind, str(actual), observed)

@pytest.mark.parametrize('value,allowed', [
    ('bob@company.test', True),
    ('eve@outside.test', False),
    ('bob@company.test, eve@outside.test', False),
    ('eve@outside.test, bob@company.test', False),
    ('bob@company.test;eve@outside.test', False),
])
def test_domain_transform_checks_all_recipients(value, allowed):
    g, _, _ = setup(modify_policy=modify('to', 'restrict_domain', allowed_domains=['company.test']))
    observed = []
    def send(to):
        observed.extend(to.replace(';', ',').split(','))
        return 'simulated sent'
    try:
        g.call('task', send, parameters={'to': value}, **AUTH)
    except DeniedError:
        pass
    assert bool(observed) == allowed, observed

@pytest.mark.parametrize('policy', ['modify', 'data_policy'])
@pytest.mark.parametrize('shape', ['text', 'structured', 'embedded'])
def test_mcp_standard_text_payloads_are_redacted(policy, shape):
    pytest.importorskip("mcp")
    from mcp.server import Server
    import mcp.types as mt
    from agentlock.integrations.mcp import AgentLockMCPServer
    cfg = ({'modify_policy': modify('output')} if policy == 'modify' else
           {'data_policy': DataPolicyConfig(prohibited_in_output=['ssn'], redaction='auto')})
    g, p, _ = setup(**cfg)
    async def handler(ctx, params):
        if shape == 'text':
            return mt.CallToolResult(content=[mt.TextContent(type='text', text=SECRET)])
        if shape == 'structured':
            return mt.CallToolResult(content=[], structured_content={'note': SECRET})
        return mt.CallToolResult(content=[mt.EmbeddedResource(type='resource',
            resource=mt.TextResourceContents(uri='file:///synthetic/note.txt', text=SECRET))])
    server = Server('local-followup', on_call_tool=handler)
    AgentLockMCPServer(server, g, {'task': p}, default_user_id='alice', default_role='user')
    response = asyncio.run(server.get_request_handler('tools/call').handler(None,
        mt.CallToolRequestParams(name='task', arguments={})))
    assert '123-45-6789' not in response.model_dump_json()

def test_data_policy_plain_string_positive_control():
    g, _, _ = setup(data_policy=DataPolicyConfig(prohibited_in_output=['ssn'], redaction='auto'))
    assert '123-45-6789' not in g.call('task', lambda: SECRET, **AUTH)

@pytest.mark.parametrize('mode', ['sync', 'async'])
@pytest.mark.parametrize('shape', ['positional_only', 'keyword_only', 'kwargs', 'partial'])
def test_transformed_parameters_rebuild_invocation(mode, shape):
    g, p, _ = setup(modify_policy=modify('body'))
    seen = []
    if shape in ('positional_only', 'partial'):
        if mode == 'sync':
            def task(body, /): seen.append(body); return 'done'
        else:
            async def task(body, /): seen.append(body); return 'done'
        args, kwargs = (SECRET,), {}
        if shape == 'partial': task, args = partial(task, SECRET), ()
    elif shape == 'keyword_only':
        if mode == 'sync':
            def task(*, body=SECRET): seen.append(body); return 'done'
        else:
            async def task(*, body=SECRET): seen.append(body); return 'done'
        args, kwargs = (), {}
    else:
        if mode == 'sync':
            def task(**kwargs): seen.append(kwargs['body']); return 'done'
        else:
            async def task(**kwargs): seen.append(kwargs['body']); return 'done'
        args, kwargs = (), {'body': SECRET}
    wrapped = agentlock(g, name='task', permissions=p)(task)
    result = wrapped(*args, **kwargs, _user_id='alice', _role='user')
    if mode == 'async': result = asyncio.run(result)
    assert result == 'done' and len(seen) == 1
    assert '123-45-6789' not in seen[0]

@pytest.mark.parametrize('presentation', ['requested', 'effective', 'omitted', 'substituted'])
def test_direct_effective_token_binding(presentation):
    g, _, _ = setup(modify_policy=modify('body'))
    a = g.authorize('task', parameters={'body': SECRET}, **AUTH)
    seen = []
    def task(body): seen.append(body); return 'done'
    kwargs = {'parameters': {'body': SECRET}}
    if presentation == 'effective': kwargs = {'effective_parameters': a.effective_parameters}
    elif presentation == 'omitted': kwargs = {}
    elif presentation == 'substituted': kwargs = {'parameters': {'body': 'different action'}}
    if presentation == 'substituted':
        with pytest.raises(TokenInvalidError): g.execute('task', task, token=a.token, **kwargs)
        assert seen == []
    else:
        assert g.execute('task', task, token=a.token, **kwargs) == 'done'
        assert seen == [a.effective_parameters['body']]
        assert '123-45-6789' not in seen[0]

def test_async_cancellation_consumes_grant(monkeypatch):
    g, p, _ = setup()
    issued = []
    issue = g.token_store.issue
    def capture(*a, **kw):
        t = issue(*a, **kw); issued.append(t); return t
    monkeypatch.setattr(g.token_store, 'issue', capture)
    async def task(): raise asyncio.CancelledError()
    wrapped = agentlock(g, name='task', permissions=p)(task)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(wrapped(_user_id='alice', _role='user'))
    assert issued[0].status.value == 'used'

def test_deferral_expiry_without_sweep():
    from agentlock import DeferralManager
    manager = DeferralManager()
    record = manager.queue_commit('session', 'task', {}, taint_at_call={})
    record.created_at -= 1000
    manager.resolve_commit_queue('session', deny=False)
    assert record.resolution == 'deny'

def test_deferred_nested_parameters_are_snapshotted():
    from agentlock import DeferralManager
    manager = DeferralManager()
    params = {'target': {'url': 'https://original.test'}}
    record = manager.queue_commit('session', 'task', params, taint_at_call={})
    params['target']['url'] = 'https://substitution.test'
    assert record.parameters['target']['url'] == 'https://original.test'


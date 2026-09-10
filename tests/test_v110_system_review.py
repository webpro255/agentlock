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

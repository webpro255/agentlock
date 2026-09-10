"""v1.10.1 follow-up: policy combinations and allowed/denied edge cases.
All data and side effects are synthetic and local.
"""
import asyncio
from pathlib import Path
import pytest
from agentlock import agentlock
from agentlock.exceptions import DeniedError
from agentlock.schema import DataPolicyConfig
from agentlock import AuthorizationGate, AgentLockPermissions
from agentlock.schema import ModifyPolicyConfig, TransformationConfig
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


@pytest.mark.parametrize('mode', ['direct', 'sync', 'async', 'mcp'])
def test_canonical_path_is_the_path_executed(tmp_path, mode):
    allowed = tmp_path / 'allowed'
    (allowed / 'nested').mkdir(parents=True)
    target = allowed / 'ok.txt'
    target.write_text('SAFE_SENTINEL')
    (allowed / 'link').symlink_to(allowed / 'nested', target_is_directory=True)
    supplied = str(allowed / 'link' / '..' / 'ok.txt')
    g, p, _ = setup(modify_policy=modify('path', 'whitelist_path', allowed_prefixes=[str(allowed)]))
    seen = []
    def task(path):
        seen.append(path)
        return Path(path).read_text()
    if mode == 'direct':
        a = g.authorize('task', parameters={'path': supplied}, **AUTH)
        result = g.execute('task', task, token=a.token, parameters={'path': supplied})
    elif mode == 'sync':
        f = agentlock(g, name='task', permissions=p)(task)
        result = f(supplied, _user_id='alice', _role='user')
    elif mode == 'async':
        async def run(path, /): return task(path)
        f = agentlock(g, name='task', permissions=p)(run)
        result = asyncio.run(f(supplied, _user_id='alice', _role='user'))
    else:
        pytest.importorskip("mcp")
        from mcp.server import Server
        import mcp.types as mt
        from agentlock.integrations.mcp import AgentLockMCPServer
        async def handler(ctx, params):
            return mt.CallToolResult(content=[mt.TextContent(type='text', text=task(**params.arguments))])
        server = Server('canonical-path', on_call_tool=handler)
        AgentLockMCPServer(server, g, {'task': p}, default_user_id='alice', default_role='user')
        response = asyncio.run(server.get_request_handler('tools/call').handler(None,
            mt.CallToolRequestParams(name='task', arguments={'path': supplied})))
        result = response.content[0].text
    assert result == 'SAFE_SENTINEL'
    assert seen == [str(target.resolve())]

@pytest.mark.parametrize('kind', ['sibling_prefix', 'relative', 'symlink_chain_outside', 'parent_of_symlink_target'])
def test_path_denials_precede_execution(tmp_path, kind):
    allowed = tmp_path / 'allowed'
    allowed.mkdir()
    other = tmp_path / 'allowed-other'
    (other / 'child').mkdir(parents=True)
    (other / 'secret').write_text('PRIVATE_SENTINEL')
    (allowed / 'first').symlink_to(allowed / 'second')
    (allowed / 'second').symlink_to(other / 'child', target_is_directory=True)
    supplied = {
        'sibling_prefix': str(other / 'secret'),
        'relative': 'allowed/ok.txt',
        'symlink_chain_outside': str(allowed / 'first'),
        'parent_of_symlink_target': str(allowed / 'first' / '..' / 'secret'),
    }[kind]
    g, _, _ = setup(modify_policy=modify('path', 'whitelist_path', allowed_prefixes=[str(allowed)]))
    seen = []
    with pytest.raises(DeniedError):
        g.call('task', lambda path: seen.append(path), parameters={'path': supplied}, **AUTH)
    assert seen == []

@pytest.mark.parametrize('recipient,permitted', [
    ('Bob<bob@company.test>', True),
    ('Bob Smith <bob@COMPANY.TEST>; carol@company.test', True),
    ('bob@company.test,, ;carol@company.test;', True),
    ('bob@company.test\tcarol@company.test', True),
    ('bob@company.test, Eve <eve@outside.test>', False),
    ('eve@outside.test;bob@company.test', False),
    ('bob@company.test eve@outside.test', False),
    ('bob@company.test;incomplete@', False),
    ('bob@[127.0.0.1]', False),
    ('bob@compаny.test', False),
    ('bob@company.test@outside.test', False),
    ('"Doe, Bob" <bob@company.test>', False),
])
def test_domain_policy_edge_forms(recipient, permitted):
    g, _, _ = setup(modify_policy=modify('to', 'restrict_domain', allowed_domains=['company.test']))
    seen = []
    try:
        g.call('task', lambda to: seen.append(to), parameters={'to': recipient}, **AUTH)
    except DeniedError:
        pass
    assert bool(seen) == permitted

@pytest.mark.parametrize('policy', ['none', 'modify', 'data_policy', 'both'])
@pytest.mark.parametrize('late_registration', [False, True])
def test_mcp_mixed_payloads_and_policy_combinations(policy, late_registration):
    pytest.importorskip("mcp")
    from mcp.server import Server
    import mcp.types as mt
    from agentlock.integrations.mcp import AgentLockMCPServer
    config = {}
    if policy in ('modify', 'both'): config['modify_policy'] = modify('output')
    if policy in ('data_policy', 'both'):
        config['data_policy'] = DataPolicyConfig(prohibited_in_output=['ssn'], redaction='auto')
    g, p, _ = setup(**config)
    async def handler(ctx, params):
        return mt.CallToolResult(content=[
            mt.TextContent(type='text', text=SECRET),
            mt.EmbeddedResource(type='resource', resource=mt.TextResourceContents(
                uri='file:///synthetic/test.txt', text=SECRET)),
            mt.TextContent(type='text', text='ordinary text remains unchanged'),
        ], structured_content={'rows': [{'note': SECRET}, {'number': 7, 'flag': True}]})
    server = Server('mixed-payloads') if late_registration else Server('mixed-payloads', on_call_tool=handler)
    AgentLockMCPServer(server, g, {'task': p}, default_user_id='alice', default_role='user')
    if late_registration: server.add_request_handler('tools/call', mt.CallToolRequestParams, handler)
    response = asyncio.run(server.get_request_handler('tools/call').handler(None,
        mt.CallToolRequestParams(name='task', arguments={})))
    assert ('123-45-6789' in response.model_dump_json()) == (policy == 'none')
    assert response.content[2].text == 'ordinary text remains unchanged'
    assert response.structured_content['rows'][1] == {'number': 7, 'flag': True}
    assert str(response.content[1].resource.uri) == 'file:///synthetic/test.txt'

def test_transformed_async_execution_has_verified_evidence():
    g, p, _ = setup(modify_policy=modify('body'))
    async def task(body): return body
    f = agentlock(g, name='task', permissions=p)(task)
    result = asyncio.run(f(SECRET, _user_id='alice', _role='user'))
    assert '123-45-6789' not in result
    records = g.audit_logger.query(tool_name='task', limit=100)
    actions = [r.action for r in records]
    assert 'execution_attempted' in actions
    assert 'execution_completed' in actions
    assert not any('unverified' in action for action in actions)

@pytest.mark.parametrize('denial_kind', ['lineage', 'timeout'])
def test_reported_execution_after_denial_is_flagged(denial_kind):
    import hashlib
    from agentlock import ContextSource
    from agentlock.schema import LineagePolicyConfig, ActionClassConfig
    g, _, sid = setup(lineage_policy=LineagePolicyConfig(enabled=True, decision='deny'),
        action_class=ActionClassConfig(is_deletion=True))
    record = g.defer_consequential(sid, 'task', {}, is_deletion=True, record_action_flags=True)
    if denial_kind == 'timeout':
        record.created_at -= 1000  # simulate expiry without waiting
    else:
        content = 'Untrusted retrieved page'
        g.notify_context_write(sid, ContextSource.WEB_CONTENT,
            hashlib.sha256(content.encode()).hexdigest(), content=content)
    resolved = g.resolve_deferred_commits(sid)
    assert len(resolved) == 1 and resolved[0].resolution in ('deny', 'denied')
    # No tool is executed: simulate the host reporting that it disobeyed a denial.
    audit = g.confirm_execution('task', deferral_id=record.deferral_id,
        parameters={}, status='succeeded')
    assert audit.action == 'execution_after_denial', (record.resolution, audit.action, audit.reason)


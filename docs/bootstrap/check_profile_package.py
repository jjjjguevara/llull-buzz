#!/usr/bin/env python3
"""Author-only validation of a hash-bound changed-document projection or Git checkout.

No application imports, network requests, mailbox access or fiscal effects. The original
check_provider_docs.py remains unchanged; this supplement adds schema, owning-ID and
amendment checks, and labels reconstructed projections rather than pretending a checkout.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import yaml
from jsonschema import Draft202012Validator, FormatChecker

LEGACY = '131e4c8e5961cadbc028678dba1df881ccd392558cb033890130153a647b5cb3'
COUNTS = {'llull-buzz': ('BZ-C',8,'BZ-R',6,'BZ',14,7,5),
          'llull-email': ('ML-C',8,'ML-R',5,'ML',13,6,4),
          'llull-cfdi': ('CFDI-IC',12,'CFDI-IR',6,'FI',14,6,3)}
FIELDS = {'id','owner','version','license','rationale','alternative','footprint','adaptation'}
CREDENTIAL = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{30,}|[?&]token=[A-Za-z0-9]{20,}')

def digest(b): return hashlib.sha256(b).hexdigest()
def blob(b): return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def unique(pairs):
    result = {}
    for key,value in pairs:
        if key in result: raise ValueError(f'duplicate key: {key}')
        result[key] = value
    return result
class Loader(yaml.SafeLoader): pass
def mapping(loader,node,deep=False):
    return unique((loader.construct_object(k,deep=deep),loader.construct_object(v,deep=deep)) for k,v in node.value)
Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,mapping)
def yload(t): return yaml.load(t,Loader=Loader)
def jload(t): return json.loads(t,object_pairs_hook=unique)
def ids(prefix,n): return [f'{prefix}{i:02}' for i in range(1,n+1)]
def table_ids(t,prefix): return re.findall(r'(?m)^\|\s*`?('+re.escape(prefix)+r'\d{2})\b',t)
def unfenced(t): return re.sub(r'(?ms)^\s*(`{3,}|~{3,})[^\n]*\n.*?^\s*\1\s*$','',t)
def anchors(t):
    found,counts = set(),{}
    for title in re.findall(r'(?m)^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$',unfenced(t)):
        title=re.sub(r'\[([^\]]+)\]\([^)]*\)',r'\1',title)
        slug=re.sub(r'[^\w\- ]','',title.lower()).replace(' ','-'); n=counts.get(slug,0)
        found.add(slug if n==0 else f'{slug}-{n}'); counts[slug]=n+1
    found.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)',t,re.I)); return found

def schema_refs(obj):
    if isinstance(obj,dict):
        for k,v in obj.items():
            if k=='$ref': yield v
            else: yield from schema_refs(v)
    elif isinstance(obj,list):
        for v in obj: yield from schema_refs(v)

def check(root,index,legacy):
    errors,files,texts,parsed,external=[],{},{},{},set(); link_count=0
    def require(ok,msg):
        if not ok: errors.append(msg)
    def exact(actual,wanted,label):
        require(len(actual)==len(set(actual)) and set(actual)==set(wanted),f'{label}: missing/extra/duplicate IDs')
    require(digest(legacy.read_bytes())==LEGACY,'preceding checker hash changed')
    cp,nc,rp,nr,p,nm,np,nu=COUNTS[index['repository'].split('/')[-1]]
    known={**index.get('known_targets',{}),**index['changed']}
    for name,meta in index['changed'].items():
        path=root/name
        if not path.resolve().is_relative_to(root) or not path.is_file() or path.is_symlink():
            errors.append('missing/unsafe changed file: '+name); continue
        b=path.read_bytes(); files[name]={'sha256':digest(b),'git_blob':blob(b),'bytes':len(b)}
        require(meta.get('sha')==blob(b),'remote blob mismatch: '+name)
        require(name.startswith(('docs/','.scratch/','.github/workflows/')) or name in {'README.md','AGENTS.md','.gitignore','LICENSE'},'out-of-scope artifact: '+name)
        try:
            t=b.decode('utf-8');texts[name]=t
            require(not b or b.endswith(b'\n'),'missing final newline: '+name)
            require('\r' not in t and re.search(r'(?m)[ \t]+$',t) is None,'line ending/whitespace: '+name)
            require(re.search(r'(?m)^(<<<<<<< |=======\s*$|>>>>>>> )',t) is None,'conflict marker: '+name)
            require(CREDENTIAL.search(t) is None,'credential pattern: '+name)
            if index['repository'].endswith('llull-buzz'):
                require(re.search(r'https://(?:github\.com|raw\.githubusercontent\.com)/jjjjguevara/(?:llull-akita|llull-email|llull-cfdi|SIMSAMEX)(?:/|\b)',t) is None,'private consumer URL in public package: '+name)
            if path.suffix in {'.yml','.yaml'}: parsed[name]=yload(t)
            elif path.suffix=='.json': parsed[name]=jload(t)
            elif path.suffix=='.py': ast.parse(t,filename=name)
            elif path.suffix=='.md':
                fence=None
                for line in t.splitlines():
                    m=re.match(r'^\s*(`{3,}|~{3,})(.*)$',line)
                    if not m: continue
                    if fence is None: fence=m[1]
                    elif m[1][0]==fence[0] and len(m[1])>=len(fence) and not m[2].strip(): fence=None
                require(fence is None,'unclosed code fence: '+name)
                if t.startswith('---\n'): parsed[name]=yload(t.split('---\n',2)[1])
        except (ValueError,UnicodeError,yaml.YAMLError,SyntaxError,IndexError) as e: errors.append(f'parse {name}: {e}')
    def link(origin,raw):
        nonlocal link_count
        link_count+=1
        try:
            u=urlsplit(raw.strip('<>'))
            if u.scheme or u.netloc:
                require(u.scheme in {'http','https','mailto'},f'URI scheme {origin}: {raw}')
                require(u.scheme=='mailto' or bool(u.hostname),f'URI host {origin}: {raw}')
                external.add(raw); return
            target=((root/origin).parent/unquote(u.path)).resolve() if u.path else root/origin
            if not target.is_relative_to(root): errors.append(f'escaping link {origin}: {raw}'); return
            name=str(target.relative_to(root))
            require(name in known or target.exists(),f'missing link {origin}: {raw}')
            if u.fragment and target.suffix=='.md':
                if not target.is_file(): errors.append(f'anchor target not materialized {origin}: {raw}')
                else: require(unquote(u.fragment) in anchors(target.read_text()),f'missing anchor {origin}: {raw}')
        except ValueError as e: errors.append(f'URI {origin}: {e}')
    for name,t in texts.items():
        if not name.endswith('.md'): continue
        clean=unfenced(t)
        for raw in re.findall(r'!?\[[^\]\n]*\]\(([^\s]+?)(?:\s+"[^"]*")?\)',clean): link(name,raw)
        for raw in re.findall(r'(?m)^\s*\[[^\]]+\]:\s*(\S+)',clean): link(name,raw)
        front=parsed.get(name,{})
        if isinstance(front,dict):
            for field in ('source_basis','implementation_binding'):
                for raw in front.get(field,[]):
                    if isinstance(raw,str) and re.match(r'^(?:\.\.?/|[\w-]+\.(?:md|json|yaml))',raw): link(name,raw)
    m=parsed.get('docs/bootstrap/PROFILE-COVERAGE.json',{})
    require(bool(m),'profile coverage manifest missing')
    contract=texts.get(m.get('contract_file'),'')
    exact(table_ids(contract,cp),ids(cp,nc),'owning capabilities')
    exact(table_ids(contract,rp),ids(rp,nr),'owning required ports')
    exact(m.get('expected_capabilities',[]),ids(cp,nc),'manifest capabilities')
    registry=parsed.get(m.get('components_path'),{}); components=registry.get('components',[])
    component_ids=[r.get('id') for r in components]
    require(bool(components) and len(component_ids)==len(set(component_ids)),'component identity uniqueness')
    for row in components:
        require(all(row.get(k) for k in FIELDS),'component fields: '+str(row.get('id')))
        require(str(row.get('version','')).lower() not in {'unselected','unresolved','pending'},'unselected component: '+str(row.get('id')))
    uat=texts.get(m.get('uat_file'),''); uat_ids=re.findall(r'(?m)^##\s+('+p+r'-UAT\d{2})\b',uat)
    exact(uat_ids,ids(p+'-UAT',nu),'owning human cases'); require('not-run' in uat,'UAT execution boundary missing')
    assurance=texts.get(m.get('assurance_file'),'')
    for pf in ids(p+'-PF',np): require(any(pf in l for l in assurance.splitlines() if l.startswith('|')),'owning proof profile missing: '+pf)
    commitments=[]; adrs=m.get('adr_files',[]);require(len(adrs)==3,'three proposed ADR owners required')
    for name in adrs:
        front=parsed.get(name,{})
        require(front.get('status')=='proposed' and front.get('decision_date') is None and front.get('approval_ref') is None,'proposal acceptance metadata: '+name)
        text=texts.get(name,''); own=table_ids(text,p+'-CMT'); commitments.extend(own)
        exact(own,front.get('ecosystem_placement',{}).get('implements_asrs',[]),'ADR commitments: '+name)
        require(bool(front.get('implementation_binding')),'ADR implementation binding: '+name)
        for ident in front.get('component_refs',[]): require(ident in component_ids,f'unknown component {ident}: {name}')
        for ident in front.get('mandatory_uat_refs',[]): require(ident in uat_ids,f'unknown human case {ident}: {name}')
        for heading in ['Status','Context','Decision','Options Considered','Rationale','Atomic Commitments and Authority','Component Selection and Dependency Binding','Trade-offs Accepted','Consequences','Acceptance and Downstream UATs','Source Basis','Review Triggers','Implementation Binding','Conformance and Drift Controls']:
            require('## '+heading in text,f'ADR heading {heading}: {name}')
    exact(commitments,ids(p+'-CMT',nm),'owning commitment definitions')
    rows=m.get('capabilities',[]); exact([r.get('id') for r in rows],ids(cp,nc),'capability proof mapping')
    for row in rows:
        require(bool(row.get('mechanism')),'capability mechanism missing: '+str(row.get('id')))
        for field,allowed in [('component_ids',component_ids),('technical_profiles',ids(p+'-PF',np)),('human_cases',uat_ids)]:
            require(bool(row.get(field)) and all(x in allowed for x in row.get(field,[])),f'capability {field}: {row.get("id")}')
    for name in m.get('required_files',[]): require(name in texts,'required artifact missing: '+name)
    for src in m.get('source_bindings',[]):
        if src.get('repository'): require(bool(re.fullmatch('[0-9a-f]{40}',src.get('commit',''))),'source commit not immutable')
    examples=0; negative=0
    for spec in m.get('schema_examples',[]):
        try:
            schema=parsed[spec['schema']]; Draft202012Validator.check_schema(schema)
            require(all(r.startswith('#/') for r in schema_refs(schema)),'external schema references prohibited')
            validator=Draft202012Validator(schema,format_checker=FormatChecker())
            for row in parsed[spec['examples']]['cases']:
                valid=validator.is_valid(row[spec.get('instance_field','instance')]); expected=row.get('schema_valid',True)
                require(valid==expected,'schema example expectation: '+row['id']); examples+=1; negative+=int(not expected)
            for row in parsed[spec['examples']]['cases']:
                value=row[spec.get('instance_field','instance')]
                if row.get('schema_valid',True) and 'payload_digest' in value and 'payload' in value:
                    raw=json.dumps(value['payload'],sort_keys=True,separators=(',',':'),ensure_ascii=True)
                    require(raw.isascii() and digest(raw.encode())==value['payload_digest'],'ASCII fixture payload digest: '+row['id'])
                    require(1<=sum(len(value['payload'][k]) for k in ('to','cc','bcc'))<=100,'aggregate fixture recipients: '+row['id'])
                if row.get('schema_valid',True) and 'claims' in value:
                    c=value['claims'];require(0<c['exp']-c['iat']<=60,'fixture assertion TTL: '+row['id'])
                    require(c['exp']<=c.get('task_expires_at',c['exp']),'fixture absolute expiry: '+row['id'])
            for vector in parsed[spec['examples']].get('vectors',[]):
                require(digest(vector['utf8'].encode())==vector['sha256'],'canonical vector digest: '+vector['id'])
        except Exception as e: errors.append(f'schema {spec.get("schema")}: {e}')
    require(bool(m.get('schema_examples')),'schema examples missing')
    # Index assertions were obtained by remote tree/diff read-back, not inferred from local files.
    for name,sha in index.get('preserved',{}).items(): require(known.get(name,{}).get('sha')==sha,'preservation mismatch: '+name)
    return {'errors':errors,'files':files,'counts':{'changed_files':len(files),'links_and_frontmatter_refs':link_count,'components':len(components),'capabilities':nc,'required_ports':nr,'commitments':nm,'technical_profiles':np,'human_cases':nu,'schema_examples':examples,'negative_schema_examples':negative},'owner_decisions_pending':m.get('owner_decisions_pending',[]),'external_links':sorted(external)}

def self_test():
    for parser,text in [(jload,'{"x":1,"x":2}'),(yload,'x: 1\nx: 2\n')]:
        try: parser(text)
        except ValueError: pass
        else: raise AssertionError('duplicate accepted')
    assert anchors('# Same\n# Same\n')=={'same','same-1'}
    assert 'hidden' not in anchors('```md\n# Hidden\n```\n')
    assert table_ids('| BZ-C01 | example |','BZ-C')==['BZ-C01']
    assert blob(b'x\n')!=blob(b'x')
    assert CREDENTIAL.search('ghp_'+'A'*40)
    v=Draft202012Validator({'type':'object','properties':{'x':{'type':'string'}},'required':['x'],'additionalProperties':False})
    assert v.is_valid({'x':'ok'}) and not v.is_valid({'x':'ok','extra':1}) and not v.is_valid({})
    print('self-test: 10 assertions passed'); return 0

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path);p.add_argument('--index',type=Path);p.add_argument('--legacy',type=Path);p.add_argument('--output',type=Path);p.add_argument('--self-test',action='store_true');a=p.parse_args()
    if a.self_test:return self_test()
    if not all([a.root,a.index,a.legacy,a.output]):p.error('root/index/legacy/output required')
    index=jload(a.index.read_text());root=a.root.resolve()
    result=check(root,index,a.legacy); rc=int(bool(result['errors']))
    result.update(evidence_type='author-documentation-validation',subject_sha=index['subject_sha'],comparison_base_sha=index['comparison_base_sha'],materialization=index['materialization'],index_source=index['source'],index_sha256=digest(a.index.read_bytes()),checker_sha256=digest(Path(__file__).read_bytes()),preceding_checker_sha256=digest(a.legacy.read_bytes()),python=sys.version,pyyaml=yaml.__version__,jsonschema=importlib.metadata.version('jsonschema'),commands=[{'argv':sys.argv,'exit':rc}],document_checks_passed=not rc,not_evidence_for=['runtime','security certification','performance','human UAT','independent review','merge approval'],external_link_check='syntax and recorded source qualification; no HTTP availability probe')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n');print(json.dumps({'subject':index['subject_sha'],'counts':result['counts'],'errors':result['errors'],'exit':rc},indent=2));return rc
if __name__=='__main__':raise SystemExit(main())

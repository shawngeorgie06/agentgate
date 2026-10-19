"""Exercise macOS launchd with temporary sample credentials; no live accounts."""
import os,sys,asyncio,subprocess,tempfile,time,socket,plistlib,re,shlex
from pathlib import Path
import requests
project=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(project))
from broker.mac_service import generate_plist
from broker.credential_store import CredentialStore
from broker.http_auth import create_token_file,read_token_file
label=f'com.agentgate.background-smoke.{os.getpid()}'
target=f'gui/{os.getuid()}/{label}'
with tempfile.TemporaryDirectory(prefix='agentgate-background-smoke-') as directory:
 config=Path(directory)
 for name in ['mcp-token','operator-token']: create_token_file(str(config/name))
 CredentialStore(str(config/'credentials.json'),'sample-only-password').store('sample-key','sample-only-value')
 (config/'policies.yaml').write_text('policies:\n  - name: sample\n    agent: "*"\n    credential: "*"\n    auto_approve: false\n    escalate: false\n')
 helper=config/'sample-helper'
 def set_helper(password=None):
  command='exit 1' if password is None else 'printf %s '+shlex.quote(password)
  helper.write_text('#!/bin/sh\necho attempt >> '+shlex.quote(str(config/'attempts'))+'\n'+command+'\n')
  helper.chmod(0o700)
 set_helper()
 with socket.socket() as reserve:
  reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
 definition=generate_plist(project,config,helper,port)
 definition['Label']=label;definition['ThrottleInterval']=1
 plist=config/'smoke.plist';plist.write_bytes(plistlib.dumps(definition));plist.chmod(0o600)
 h={'Authorization':'Bearer '+read_token_file(str(config/'operator-token'))}
 def ready():
  try: return requests.get(f'http://127.0.0.1:{port}/api/status',headers=h,timeout=1).json().get('ok') is True
  except Exception: return False
 def pid():
  r=subprocess.run(['/bin/launchctl','print',target],capture_output=True,text=True)
  m=re.search(r'\bpid = (\d+)',r.stdout)
  return m.group(1) if m else None
 def wait_ready(previous=None):
  until=time.monotonic()+15
  while time.monotonic()<until:
   current=pid()
   if current and current!=previous and ready(): return current
   time.sleep(.2)
  raise RuntimeError('Sample background broker did not become ready.')
 def wait_paused(attempts):
  until=time.monotonic()+15
  while time.monotonic()<until:
   result=subprocess.run(['/bin/launchctl','print',target],capture_output=True,text=True)
   if 'last exit code = 0' in result.stdout and pid() is None: break
   time.sleep(.2)
  else: raise RuntimeError('Failed unlock did not pause sample background startup.')
  time.sleep(2.5)  # Longer than this sample job's restart throttle.
  assert pid() is None,'Failed unlock restarted without operator intervention.'
  assert len((config/'attempts').read_text().splitlines())==attempts,'Unlock was retried automatically.'
  assert 'Background startup paused.' in (config/'broker.stderr.log').read_text()
 def retry():
  result=subprocess.run(['/bin/launchctl','kickstart',target],capture_output=True)
  assert result.returncode==0,'Sample background retry failed.'
 try:
  r=subprocess.run(['/bin/launchctl','bootstrap',f'gui/{os.getuid()}',str(plist)],capture_output=True)
  assert r.returncode==0,'Sample launchd bootstrap failed.'
  wait_paused(1);print('Missing saved unlock: paused without repeated helper calls')
  set_helper('sample-wrong-password');retry()
  wait_paused(2);print('Incorrect saved unlock: paused without repeated helper calls')
  set_helper('sample-only-password');retry()
  first=wait_ready();print('Headless launchd broker: authenticated app ready')
  r=subprocess.run(['/bin/launchctl','kill','SIGTERM',target],capture_output=True)
  assert r.returncode==0,'Sample stop failed.'
  second=wait_ready(first);print('Crash/exit supervision: restarted with a new process')
  logs=''.join(p.read_text() for p in [config/'broker.stdout.log',config/'broker.stderr.log'] if p.exists())
  for value in ['sample-only-password','sample-wrong-password','sample-only-value',read_token_file(str(config/'mcp-token')),read_token_file(str(config/'operator-token'))]: assert value not in logs
  print('Sample startup logs: no passwords or bearer credentials')
 finally:
  subprocess.run(['/bin/launchctl','bootout',target],capture_output=True)
  until=time.monotonic()+8
  while pid() is not None and time.monotonic()<until: time.sleep(.1)
  assert pid() is None,'Sample LaunchAgent cleanup failed.'
  print('Sample LaunchAgent removed')

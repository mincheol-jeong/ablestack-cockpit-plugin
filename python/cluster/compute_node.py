#!/usr/bin/env python3
"""Ceph HCI compute-node enrollment. No VM, OSD or PCS membership operations.

Public actions accept JSON on stdin; SSH transports credentials on stdin, never
in argv or logs. Fresh hosts delegate enrollment to an existing HCI coordinator.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

PLUGIN = Path('/usr/share/cockpit/ablestack')
CONFIG = PLUGIN / 'tools/properties/cluster.json'
CCVM_CONFIG = Path('/etc/cluster.json')
STATUS = PLUGIN / 'tools/properties/ablestack.json'
STATE = Path('/var/lib/ablestack/compute-nodes')
MANIFEST = STATE / 'enrollment.json'
HCI = 'ablestack-hci'
HOSTS = Path('/etc/hosts')
CHRONY = Path('/etc/chrony.conf')
SSH_DIR = Path('/root/.ssh')
CEPH_DIR = Path('/etc/ceph')
NWFILTER_XML = Path('/usr/local/sbin/nwfilter-allow-all.xml')
NWFILTER_NAMES = ('allow-all-traffic', 'allow-traffic', 'allow-all')
BRIDGE_MODULE_CONF = Path('/etc/modules-load.d/ablestack-br-netfilter.conf')
BRIDGE_SYSCTL_CONF = Path('/etc/sysctl.d/90-ablestack-bridge.conf')
BRIDGE_MODULE = Path('/sys/module/br_netfilter')
BRIDGE_KEYS = ['net.bridge.bridge-nf-call-' + name for name in ('arptables', 'iptables', 'ip6tables')]
EMPTY_HOSTS = ('127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n'
               '::1 localhost localhost.localdomain localhost6 localhost6.localdomain6\n')


def read_json(path, default=None):
    if not path.exists() and default is not None:
        return copy.deepcopy(default)
    return json.loads(path.read_text())


def atomic_write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(content if isinstance(content, bytes) else content.encode())
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_json(path, value):
    mode = stat.S_IMODE(Path(path).stat().st_mode) if Path(path).exists() else 0o600
    atomic_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', mode)


def run(argv, input_text=None, timeout=30, check=True):
    result = subprocess.run(argv, input=input_text, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Commands may contain secrets. Do not include argv or raw stderr.
        label = Path(argv[0]).name
        if label == 'virsh':
            commands = {'list', 'nwfilter-list', 'nwfilter-define', 'nwfilter-dumpxml', 'nwfilter-undefine',
                        'secret-list', 'secret-define', 'secret-dumpxml', 'secret-get-value', 'secret-set-value', 'secret-undefine'}
            label += ' ' + next((word for word in argv[1:] if word in commands), '')
        raise RuntimeError(f'{label.strip()} 명령 실패 (exit {result.returncode})')
    return result


def is_compute(host):
    return host.get('role') == 'compute'


def same_host(a, b):
    return a.lower().rstrip('.') == b.lower().rstrip('.') or a.split('.')[0].lower() == b.split('.')[0].lower()


def local_host(config):
    return next((h for h in config['clusterConfig']['hosts'] if same_host(h['hostname'], socket.gethostname())), None)


def validate_node(data, config):
    name = str(data.get('hostname', '')).strip().lower()
    short_name = name.split('.')[0]
    if (len(name) > 253 or not name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in name.split('.'))
            or short_name in ('localhost', 'ablecube', 'scvm', 'ccvm', 'ccvm-mngt', 'gwvm', 'gwvm-mngt')
            or re.fullmatch(r'pn-ablecube\d*', short_name) or 'scvm' in name):
        raise ValueError('유효한 호스트명을 입력하십시오. 예약 이름과 scvm 이름은 사용할 수 없습니다.')
    node = {'hostname': name, 'role': 'compute'}
    for key in ('ablecube', 'ablecubePn'):
        address = ipaddress.IPv4Address(str(data.get(key, '')).strip())
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
            raise ValueError('관리 IP와 HPN IP에는 호스트에 할당된 IPv4 주소를 입력하십시오.')
        node[key] = str(address)
    if node['ablecube'] == node['ablecubePn']:
        raise ValueError('관리 IP와 HPN IP는 서로 달라야 합니다.')
    root = config['clusterConfig']
    existing_node = next((host for host in root['hosts'] if same_host(host['hostname'], name)), None)
    if existing_node and not is_compute(existing_node):
        raise ValueError('기존 HCI 호스트는 컴퓨팅 노드 추가로 변경할 수 없습니다.')
    for host in root['hosts']:
        if host is existing_node:
            continue
        existing = {host.get(k) for k in ('ablecube', 'ablecubePn', 'scvmMngt', 'scvm', 'scvmCn')}
        if existing.intersection((node['ablecube'], node['ablecubePn'])):
            raise ValueError('클러스터에서 이미 사용하는 IP입니다.')
    for vm in ('ccvm', 'gwvm', 'pfmp'):
        if set(root.get(vm, {}).values()).intersection((node['ablecube'], node['ablecubePn'])):
            raise ValueError('클러스터 VM에서 이미 사용하는 IP입니다.')
    node['index'] = str(existing_node['index']) if existing_node else str(max([int(h['index']) for h in root['hosts']] + [0]) + 1)
    return {key: node[key] for key in ('index', 'hostname', 'ablecube', 'ablecubePn', 'role')}


def assert_compute_target(config, hostname):
    node = next((h for h in config['clusterConfig']['hosts'] if h['hostname'] == hostname), None)
    if not node or not is_compute(node):
        raise ValueError('컴퓨팅 노드만 제거할 수 있습니다.')
    if same_host(node['hostname'], socket.gethostname()):
        raise ValueError('제거할 노드가 아닌 기존 HCI 호스트에서 실행하십시오.')
    pcs = set(config['clusterConfig'].get('pcsCluster', {}).values())
    if pcs.intersection((node['hostname'], node['ablecube'], node['ablecubePn'])):
        raise ValueError('PCS 구성원은 컴퓨팅 노드 설정 제거 대상이 아닙니다.')
    return node


def participants(config):
    result = []
    for host in config['clusterConfig']['hosts']:
        result.append({'ip': host['ablecube'], 'hostname': host['hostname'], 'kind': 'host'})
        if not is_compute(host) and host.get('scvmMngt'):
            result.append({'ip': host['scvmMngt'], 'hostname': 'scvm' + str(host['index']), 'kind': 'vm'})
    ccvm = config['clusterConfig'].get('ccvm', {}).get('ip')
    if ccvm:
        result.append({'ip': ccvm, 'hostname': 'ccvm', 'kind': 'ccvm'})
    return list({p['ip']: p for p in result}.values())


def host_entries(config, local_name, compute_only=False):
    entries = []
    for host in config['clusterConfig']['hosts']:
        if compute_only and not is_compute(host):
            continue
        idx = str(host['index'])
        own = same_host(host['hostname'], local_name)
        entries.append((host['ablecube'], [host['hostname']] + (['ablecube'] if own else [])))
        if host.get('ablecubePn'):
            entries.append((host['ablecubePn'], ['pn-ablecube' + idx] + (['pn-ablecube'] if own else [])))
        if not is_compute(host):
            for key, alias, local_alias in [('scvmMngt', 'scvm' + idx + '-mngt', 'scvm-mngt'), ('scvm', 'scvm' + idx, 'scvm'), ('scvmCn', 'cn-scvm' + idx, 'cn-scvm')]:
                if host.get(key):
                    entries.append((host[key], [alias] + ([local_alias] if own else [])))
    if not compute_only:
        ccvm = config['clusterConfig'].get('ccvm', {}).get('ip')
        if ccvm:
            entries.append((ccvm, ['ccvm-mngt', 'ccvm']))
        gwvm = config['clusterConfig'].get('gwvm', {})
        if gwvm.get('ip'):
            entries.append((gwvm['ip'], ['gwvm-mngt']))
        if gwvm.get('pn'):
            entries.append((gwvm['pn'], ['gwvm']))
    return entries


def merge_hosts(text, entries, removed=()):
    """Update owned aliases, preserving localhost, comments and unrelated aliases."""
    names = {name for _, aliases in entries for name in aliases} | set(removed)
    lines = []
    for line in text.splitlines():
        body, sep, comment = line.partition('#')
        fields = body.split()
        if len(fields) < 2:
            lines.append(line)
            continue
        kept = [name for name in fields[1:] if name not in names]
        if kept == fields[1:]:
            lines.append(line)
        elif kept:
            lines.append(fields[0] + '\t' + ' '.join(kept) + ((' #' + comment) if sep else ''))
        elif sep:
            lines.append('#' + comment)
    lines.extend(ip + '\t' + ' '.join(aliases) for ip, aliases in entries)
    return '\n'.join(lines).rstrip() + '\n'


def configure_host_network(manifest):
    if run(['systemctl', 'is-active', '--quiet', 'openvswitch'], check=False).returncode == 0:
        manifest.setdefault('network', {'managed': False})
        save_json(MANIFEST, manifest)
        return 'Open vSwitch 사용: 기존 nwfilter 정책 유지'
    if 'network' not in manifest or not manifest['network'].get('managed'):
        loaded = BRIDGE_MODULE.exists()
        values = {key: run(['sysctl', '-n', key]).stdout.strip() for key in BRIDGE_KEYS} if loaded else {}
        manifest['network'] = {'managed': True, 'module_loaded_before': loaded, 'bridge_before': values}
        save_json(MANIFEST, manifest)
    filters = run(['virsh', 'nwfilter-list']).stdout
    filter_name = next((name for name in NWFILTER_NAMES if name in filters.split()), None)
    if not filter_name and NWFILTER_XML.is_file():
        filter_name = ET.fromstring(NWFILTER_XML.read_text()).get('name')
    if filter_name not in NWFILTER_NAMES:
        raise ValueError('nwfilter 정의 파일을 확인하십시오: ' + str(NWFILTER_XML))
    recorded = manifest['network'].get('filter_xml')
    if recorded and ET.fromstring(recorded).get('name') != filter_name:
        manifest['network'].pop('filter_xml')
    manifest['network']['filter_name'] = filter_name
    save_json(MANIFEST, manifest)
    if filter_name not in filters.split():
        run(['virsh', 'nwfilter-define', '--file', str(NWFILTER_XML)])
    if 'filter_xml' not in manifest['network']:
        manifest['network']['filter_xml'] = run(['virsh', 'nwfilter-dumpxml', filter_name]).stdout
    save_json(MANIFEST, manifest)
    run(['modprobe', 'br_netfilter'])
    tracked_write(BRIDGE_MODULE_CONF, 'br_netfilter\n', 0o644, manifest)
    settings = '\n'.join('net.bridge.bridge-nf-call-' + name + '=1' for name in ('arptables', 'iptables', 'ip6tables')) + '\n'
    tracked_write(BRIDGE_SYSCTL_CONF, settings, 0o644, manifest)
    run(['sysctl', '-p', str(BRIDGE_SYSCTL_CONF)])
    return 'nwfilter 및 bridge 설정 완료'


def reset_cluster_config():
    return {'clusterConfig': {'type': '', 'backup_path': '', 'ccvm': {'ip': ''},
        'gwvm': {'ip': '', 'pn': ''}, 'pfmp': {'ingress_ip': ''},
        'mngtNic': {'cidr': '', 'gw': '', 'dns': ''},
        'pcsCluster': {'hostname1': '', 'hostname2': '', 'hostname3': ''},
        'hosts': [], 'extenal_timeserver': '', 'iscsi_storage': 'false'}}


def cleanup_host_network(manifest):
    network = manifest.get('network', {})
    # Older enrollments used these same dedicated files but did not journal the network.
    managed = network.get('managed', BRIDGE_MODULE_CONF.exists() or BRIDGE_SYSCTL_CONF.exists())
    if not managed or manifest.get('network_cleaned'):
        return
    filters = run(['virsh', 'nwfilter-list']).stdout
    filter_name = network.get('filter_name')
    if not filter_name:
        filter_name = ET.fromstring(network['filter_xml']).get('name') if network.get('filter_xml') else next((name for name in NWFILTER_NAMES if name in filters.split()), None)
    if filter_name in NWFILTER_NAMES and filter_name in filters.split():
        xml = run(['virsh', 'nwfilter-dumpxml', filter_name]).stdout
        if network.get('filter_xml') and ET.tostring(ET.fromstring(xml)) != ET.tostring(ET.fromstring(network['filter_xml'])):
            raise ValueError('가입 이후 allow-all nwfilter가 변경되었습니다. 확인 후 제거하십시오.')
        run(['virsh', 'nwfilter-undefine', filter_name])
    if BRIDGE_MODULE.exists():
        for key in BRIDGE_KEYS:
            run(['sysctl', '-w', key + '=' + network.get('bridge_before', {}).get(key, '0')])
        if network.get('module_loaded_before') is False:
            run(['modprobe', '-r', 'br_netfilter'])
    manifest['network_cleaned'] = True
    save_json(MANIFEST, manifest)


def cleanup_compute_host(node):
    manifest = read_json(MANIFEST)
    if manifest.get('state') == 'removed' and manifest['node'] == node:
        return '대상 호스트 가입 설정은 이미 초기화되었습니다.'
    probe(node)
    if manifest['node'] != node:
        raise ValueError('가입 기록과 제거 대상이 다릅니다.')
    targets = manifest.get('reset_targets', {})
    conflicts = []
    for path, entry in manifest['files'].items():
        # These files are refreshed by normal cluster preparation/synchronization.
        # Removal explicitly resets hosts and restores the pre-enrollment time settings.
        if path in (str(HOSTS), str(CHRONY)):
            snapshot(path)  # Keep the symlink guard even for resettable files.
            continue
        before = entry['before']
        hashes = {entry['applied'], hashlib.sha256(base64.b64decode(before['data'])).hexdigest() if before else None}
        if path in targets:
            content = targets[path]['data']
            hashes.add(hashlib.sha256(base64.b64decode(content)).hexdigest() if content is not None else None)
        if digest(path) not in hashes:
            conflicts.append(path)
    if conflicts:
        raise ValueError('가입 이후 변경된 파일을 먼저 확인하십시오: ' + ', '.join(conflicts))
    if 'reset_targets' not in manifest:
        targets = {path: copy.deepcopy(entry['before']) if entry['before'] else {'data': None, 'mode': 0o600}
                   for path, entry in manifest['files'].items()}
        # Enrollment's Ceph credentials must not remain on a removed compute host,
        # including files already present before enrollment.
        for path in manifest['files']:
            if Path(path).parent == CEPH_DIR:
                targets[path] = {'data': None, 'mode': 0o600}
        def target(path, content, mode=0o644):
            snapshot(path)  # Refuse symlinks before touching a reset target.
            targets[str(path)] = {'data': base64.b64encode(content.encode()).decode() if content is not None else None, 'mode': mode}
        target(HOSTS, EMPTY_HOSTS)
        target(CONFIG, json.dumps(reset_cluster_config(), ensure_ascii=False, indent=2) + '\n')
        for name in ('id_rsa', 'id_rsa.pub', 'temp_id_rsa', 'temp_id_rsa.pub'):
            target(SSH_DIR / name, None, 0o600)
        network = manifest.get('network', {})
        if network.get('managed', BRIDGE_MODULE_CONF.exists() or BRIDGE_SYSCTL_CONF.exists()):
            target(BRIDGE_MODULE_CONF, None)
            target(BRIDGE_SYSCTL_CONF, None)
        pub = SSH_DIR / 'id_rsa.pub'
        manifest.setdefault('cluster_public_key', pub.read_text().strip() if pub.exists() else manifest.get('authorized_key', ''))
        cluster = read_json(CONFIG, manifest.get('config_before', {}))
        aliases = {name for ip, names in host_entries(cluster, node['hostname']) for name in [ip, *names]}
        known = []
        for alias in sorted(aliases):
            match = re.search(r'^port (\d+)$', run(['ssh', '-G', alias]).stdout, re.M)
            known.extend([alias, '[' + alias + ']:' + (match.group(1) if match else '22')])
        manifest['known_hosts_remove'] = known
        for path, entry in targets.items():
            snapshot(path)
            entry['expected'] = digest(path)
        manifest['reset_targets'] = targets
        manifest['state'] = 'resetting'
        save_json(MANIFEST, manifest)
    for path, entry in targets.items():
        reset_hash = hashlib.sha256(base64.b64decode(entry['data'])).hexdigest() if entry['data'] is not None else None
        if digest(path) not in (entry['expected'], reset_hash):
            raise ValueError('초기화 도중 변경된 파일을 먼저 확인하십시오: ' + path)
    # Failures here keep SSH authorization available for retry.
    cleanup_host_network(manifest)
    for uid, original in manifest['secrets'].items():
        if original:
            set_secret(dict(original, uuid=uid))
        elif run(['virsh', 'secret-dumpxml', uid], check=False).returncode == 0:
            run(['virsh', 'secret-undefine', uid])
    identity_paths = {str(SSH_DIR / name) for name in ('id_rsa', 'id_rsa.pub', 'temp_id_rsa', 'temp_id_rsa.pub')}
    for path, entry in targets.items():
        if path in identity_paths:
            continue
        if entry['data'] is None:
            Path(path).unlink(missing_ok=True)
        else:
            atomic_write(path, base64.b64decode(entry['data']), entry['mode'])
    status = read_json(STATUS, {})
    bootstrap = status.setdefault('bootstrap', {})
    for key in set(bootstrap) | {'scvm', 'ccvm', 'pfmp', 'gfs_configure', 'local_configure'}:
        bootstrap[key] = 'false'
    status['monitoring'] = {'wall': 'false'}
    status.pop('compute', None)
    save_json(STATUS, status)
    known = SSH_DIR / 'known_hosts'
    if known.exists():
        for alias in manifest['known_hosts_remove']:
            run(['ssh-keygen', '-R', alias, '-f', str(known)])
    if shutil.which('restorecon'):
        run(['restorecon', '-RF', str(SSH_DIR), '/etc/ceph'])
    if str(CHRONY) in manifest['files'] and CHRONY.exists():
        run(['systemctl', 'restart', 'chronyd'])
    # Revoke the shared key last, including a key imported before enrollment was journaled.
    public = manifest.get('cluster_public_key', '').split()
    key_blob = public[1] if len(public) >= 2 else None
    auth = SSH_DIR / 'authorized_keys'
    for path in identity_paths:
        Path(path).unlink(missing_ok=True)
    if key_blob and auth.exists():
        snapshot(auth)
        lines = [line for line in auth.read_text().splitlines() if key_blob not in line.split()]
        atomic_write(auth, '\n'.join(lines) + ('\n' if lines else ''), 0o600)
    save_json(MANIFEST, {'node': node, 'state': 'removed'})
    return '대상 호스트 SSH·클러스터 구성·완료 상태·nwfilter 초기화 완료'


def snapshot(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('심볼릭 링크 설정 파일은 자동으로 덮어쓰지 않습니다: ' + str(path))
    if not path.exists():
        return None
    return {'data': base64.b64encode(path.read_bytes()).decode(), 'mode': stat.S_IMODE(path.stat().st_mode)}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).exists() else None


def tracked_write(path, content, mode, manifest):
    key = str(path)
    if key in manifest['files']:
        previous = manifest['files'][key]
        before = previous['before']
        before_hash = hashlib.sha256(base64.b64decode(before['data'])).hexdigest() if before else None
        if digest(path) not in (previous.get('applied'), before_hash):
            raise ValueError('가입 이후 변경된 파일입니다: ' + key)
    entry = manifest['files'].setdefault(key, {'before': snapshot(path)})
    # Journal before the write, so interrupted attempts remain recoverable.
    entry['applied'] = hashlib.sha256(content if isinstance(content, bytes) else content.encode()).hexdigest()
    save_json(MANIFEST, manifest)
    atomic_write(path, content, mode)


def ssh_args(ip):
    ipaddress.IPv4Address(ip)
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2', '-o', 'StrictHostKeyChecking=accept-new', 'root@' + ip]


def remote(ip, action, payload, identity=None):
    if ip in local_addresses():
        return remote_action(action, payload)
    # Source is code only. Credentials and config go over stdin, never command arguments.
    source = globals().get('_transport_source') or Path(globals().get('__file__', str(PLUGIN / 'python/cluster/compute_node.py'))).read_text()
    # Retain the same source across coordinator -> target hops, even when the
    # coordinator's installed script has not received the latest fixes yet.
    loader = "import base64, sys\n_transport_source = base64.b64decode(sys.stdin.readline()).decode()\nexec(compile(_transport_source, '<compute_node>', 'exec'))"
    command = 'python3 -c ' + shlex.quote(loader) + ' _remote ' + shlex.quote(action)
    argv = ssh_args(ip)
    if identity:
        argv[1:1] = ['-i', str(identity), '-o', 'IdentitiesOnly=yes']
    wire = base64.b64encode(source.encode()).decode() + '\n' + json.dumps(payload)
    response = run(argv + [command], wire, timeout=1800 if action in ('coordinate', 'join-coordinate') else 300)
    result = json.loads(response.stdout)
    if result['code'] not in (200, 207):
        raise RuntimeError(result['val'])
    return result['val']


def local_addresses():
    addresses = {'127.0.0.1'}
    for interface in json.loads(run(['ip', '-j', '-4', 'address', 'show']).stdout):
        addresses.update(info['local'] for info in interface.get('addr_info', []) if info.get('family') == 'inet')
    return addresses


def probe(node=None, compatibility=False):
    if not PLUGIN.is_dir():
        raise ValueError('ABLESTACK Cockpit 플러그인이 설치되어 있지 않습니다.')
    if compatibility:
        reader = PLUGIN / 'python/cluster/cluster_hosts_setting.py'
        if 'is_compute' not in reader.read_text():
            raise ValueError('기존 호스트의 플러그인을 컴퓨팅 노드 지원 버전으로 먼저 업데이트하십시오.')
    result = {'hostname': socket.gethostname(), 'addresses': sorted(local_addresses())}
    if compatibility and CONFIG.exists():
        result['config'] = read_json(CONFIG)
    if node:
        if not same_host(result['hostname'], node['hostname']):
            raise ValueError('실제 호스트명과 입력한 호스트명이 다릅니다.')
        if not {node['ablecube'], node['ablecubePn']}.issubset(result['addresses']):
            raise ValueError('관리 IP와 HPN IP를 실제 NIC에 먼저 설정하십시오.')
        domains = run(['virsh', '-c', 'qemu:///system', 'list', '--all', '--name']).stdout.split()
        if domains:
            raise ValueError('VM 정의가 남아 있습니다. Mold에서 VM/로컬 디스크를 정리하십시오: ' + ', '.join(domains))
        if Path('/etc/corosync/corosync.conf').exists():
            raise ValueError('기존 PCS 설정이 있는 호스트는 컴퓨팅 전용 노드로 처리할 수 없습니다.')
    return result


def compute_status(status, cluster_status):
    # Completion flags are UI state; they do not create a local SCVM.
    status.setdefault('bootstrap', {}).update({'ccvm': 'true', 'scvm': 'true'})
    status['monitoring'] = copy.deepcopy(cluster_status.get('monitoring', {}))
    status['monitoring']['wall'] = 'true'
    status['compute'] = {'configured': True}
    return status


def remote_action(action, data):
    if action == 'join-coordinate':
        requested = data['action']
        if requested not in ('list', 'preflight-add', 'add', 'retry'):
            raise ValueError('지원하지 않는 추가 작업입니다.')
        current = read_json(CONFIG)
        require_coordinator(current)
        # The uploaded file identifies the coordinator; live membership is read there.
        if requested == 'retry':
            identifier = str(data.get('payload', {}).get('id', ''))
            if not re.fullmatch(r'[0-9a-f]{32}', identifier):
                raise ValueError('유효하지 않은 작업 ID입니다.')
            if read_json(STATE / ('operation-' + identifier + '.json')).get('action') != 'add':
                raise ValueError('컴퓨팅 노드 추가 작업만 재시도할 수 있습니다.')
        result = public_action(requested, data.get('payload', {}))
        if requested == 'list':
            result['config'] = read_json(CONFIG)
        return result
    if action == 'coordinate':
        if data['action'] not in ('list', 'preflight-add', 'add', 'preflight-remove', 'remove', 'retry', 'cleanup-offline'):
            raise ValueError('지원하지 않는 관리 작업입니다.')
        return public_action(data['action'], data.get('payload', {}))
    if action == 'probe':
        result = probe(data.get('node'), data.get('compatibility', False))
        if data.get('joining'):
            previous = read_json(CONFIG, {'clusterConfig': {'hosts': []}})
            manifest = read_json(MANIFEST, {})
            if previous.get('clusterConfig', {}).get('hosts') and not is_compute(local_host(previous) or {}) and manifest.get('state') not in ('preparing', 'prepared'):
                raise ValueError('이미 클러스터에 등록된 호스트입니다.')
        if data.get('removing') and not MANIFEST.exists():
            raise ValueError('컴퓨팅 노드 가입 기록을 찾을 수 없습니다. 자동으로 파일을 삭제하지 않습니다.')
        return result
    if action == 'sync':
        cfg = data['config']
        config_path = CCVM_CONFIG if data['kind'] == 'ccvm' else CONFIG
        current = read_json(config_path, {})
        # Preserve the node's unrelated settings and local aliases.
        old_nodes = current.get('clusterConfig', {}).get('hosts', [])
        removed = [alias for h in old_nodes if is_compute(h) for alias in (h['hostname'], 'pn-ablecube' + str(h['index']))]
        host_text = merge_hosts(HOSTS.read_text(), host_entries(cfg, socket.gethostname(), True), removed)
        manifest = read_json(MANIFEST, {})
        if manifest.get('state') in ('preparing', 'prepared'):
            tracked_write(HOSTS, host_text, 0o644, manifest)
        else:
            atomic_write(HOSTS, host_text, 0o644)
        save_json(config_path, cfg)
        if data.get('removed'):
            known = Path('/root/.ssh/known_hosts')
            if known.exists():
                for host in data['removed']:
                    port = run(['ssh', '-G', host]).stdout
                    match = re.search(r'^port (\d+)$', port, re.M)
                    for entry in (host, '[' + host + ']:' + (match.group(1) if match else '22')):
                        run(['ssh-keygen', '-R', entry, '-f', str(known)])
        return '설정 동기화 완료'
    if action == 'prepare':
        node = data['node']
        probe(node)
        existing = read_json(CONFIG, {'clusterConfig': {'hosts': []}})
        old_manifest = read_json(MANIFEST, {})
        if old_manifest.get('state') == 'removed':
            MANIFEST.unlink()
        if existing.get('clusterConfig', {}).get('hosts') and not is_compute(local_host(existing) or {}) and not MANIFEST.exists():
            raise ValueError('이미 구성된 호스트입니다. 기존 설정을 먼저 확인하십시오.')
        manifest = read_json(MANIFEST, {'node': node, 'config_before': existing, 'files': {}, 'secrets': {}, 'state': 'preparing'})
        if not same_host(manifest['node']['hostname'], node['hostname']) or str(manifest['node']['index']) != str(node['index']):
            raise ValueError('다른 가입 작업의 기록이 남아 있습니다.')
        manifest['node'] = node
        save_json(MANIFEST, manifest)
        for path, item in data['files'].items():
            tracked_write(path, base64.b64decode(item['data']), item['mode'], manifest)
        pub = base64.b64decode(data['files']['/root/.ssh/id_rsa.pub']['data']).decode().strip()
        manifest['cluster_public_key'] = pub
        save_json(MANIFEST, manifest)
        auth = Path('/root/.ssh/authorized_keys')
        text = auth.read_text() if auth.exists() else ''
        if pub not in text.splitlines():
            manifest['authorized_key'] = pub
            save_json(MANIFEST, manifest)
            atomic_write(auth, text.rstrip() + '\n' + pub + '\n', 0o600)
        os.chmod('/root/.ssh', 0o700)
        if shutil.which('restorecon'):
            run(['restorecon', '-RF', '/root/.ssh', '/etc/ceph'])
        configure_host_network(manifest)
        status = read_json(STATUS, {})
        # Shared status describes the cluster, not whether this host was patched.
        manifest.setdefault('status_before', copy.deepcopy(status))
        compute_status(status, data['status'])
        save_json(MANIFEST, manifest)
        save_json(STATUS, status)
        entries = host_entries(data['config'], node['hostname'])
        tracked_write('/etc/hosts', merge_hosts(Path('/etc/hosts').read_text(), entries, ('scvm', 'scvm-mngt', 'cn-scvm')), 0o644, manifest)
        for secret in data['secrets']:
            uid = secret['uuid']
            if uid not in manifest['secrets']:
                old = run(['virsh', 'secret-dumpxml', uid], check=False)
                manifest['secrets'][uid] = None if old.returncode else {'xml': old.stdout, 'value': run(['virsh', 'secret-get-value', uid]).stdout.strip()}
                save_json(MANIFEST, manifest)
            set_secret(secret)
        for host in data['config']['clusterConfig']['hosts']:
            if not is_compute(host) and host.get('scvm'):
                run(['ping', '-I', node['ablecubePn'], '-c', '1', '-W', '3', host['scvm']], timeout=8)
        for peer in data['peers']:
            run(ssh_args(peer['ip']) + ['true'], timeout=20)
        # RBD client connectivity, including OSD access to pools this client can list.
        run(['ceph', '-s'], timeout=25)
        run(['rbd', 'ls'], timeout=30)
        if CHRONY.exists():
            run(['systemctl', 'restart', 'chronyd'])
        manifest['state'] = 'prepared'
        save_json(MANIFEST, manifest)
        # Config is committed only by the coordinator's sync phase.
        return 'SSH·스토리지·nwfilter 준비 및 검증 완료'
    if action == 'cleanup':
        return cleanup_compute_host(data['node'])
    raise ValueError('지원하지 않는 원격 작업입니다.')


def set_secret(secret):
    # libvirt accepts XML on stdin via /dev/stdin; the key itself also stays off argv.
    run(['virsh', 'secret-define', '/dev/stdin'], secret['xml'])
    fd, name = tempfile.mkstemp(prefix='ablestack-secret-')
    try:
        with os.fdopen(fd, 'w') as file:
            file.write(secret['value'])
        run(['virsh', 'secret-set-value', '--secret', secret['uuid'], '--file', name])
    finally:
        os.unlink(name)


def source_bundle(config, node):
    paths = [Path('/root/.ssh/id_rsa'), Path('/root/.ssh/id_rsa.pub'), Path('/root/.ssh/config'), CHRONY]
    paths += sorted(CEPH_DIR.glob('*'))
    paths += [Path('/etc/cloudstack/agent') / name for name in ('tpm.properties', 'uefi.properties')]
    files = {}
    for path in paths:
        if path.is_file():
            files[str(path)] = snapshot(path)
    for needed in ('/root/.ssh/id_rsa', '/root/.ssh/id_rsa.pub', str(CEPH_DIR / 'ceph.conf'), str(CEPH_DIR / 'ceph.client.admin.keyring')):
        if needed not in files:
            raise ValueError('기존 호스트에서 필수 파일을 찾을 수 없습니다: ' + needed)
    public = run(['ssh-keygen', '-y', '-f', '/root/.ssh/id_rsa']).stdout.split()[:2]
    if public != Path('/root/.ssh/id_rsa.pub').read_text().split()[:2]:
        raise ValueError('기존 SSH 개인키와 공개키가 일치하지 않습니다.')
    files['/root/.ssh/id_rsa']['mode'] = 0o600
    files['/root/.ssh/id_rsa.pub']['mode'] = 0o644
    secrets = []
    for line in run(['virsh', 'secret-list']).stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            uid = str(uuid.UUID(parts[0]))
        except ValueError:
            continue
        xml = run(['virsh', 'secret-dumpxml', uid]).stdout
        if ET.fromstring(xml).find("usage[@type='ceph']") is not None:
            secrets.append({'uuid': uid, 'xml': xml, 'value': run(['virsh', 'secret-get-value', uid]).stdout.strip()})
    if not secrets:
        raise ValueError('기존 호스트에서 Ceph libvirt secret을 찾을 수 없습니다.')
    return {'node': node, 'config': config, 'files': files, 'secrets': secrets, 'status': read_json(STATUS), 'peers': participants(config)}


def require_coordinator(config):
    host = local_host(config)
    if config['clusterConfig']['type'] != HCI or not host or is_compute(host):
        raise ValueError('구성된 ABLESTACK HCI 호스트에서 실행하십시오.')
    return host


def inventory(config):
    operations = [read_json(path) for path in STATE.glob('operation-*.json')]
    nodes = [dict(h) for h in config['clusterConfig']['hosts'] if is_compute(h)]
    return {'nodes': nodes, 'operations': [o for o in operations if o['state'] != 'complete'], 'cleanupPending': [o for o in operations if o['state'] == 'complete' and o.get('offline') and not o.get('cleanupDone')], 'localRole': (local_host(config) or {}).get('role', 'hci'), 'supported': config['clusterConfig']['type'] == HCI}


def preflight(config, node, adding, offline=False):
    results = []
    peers = participants(config)
    for peer in peers:
        if not adding and peer['ip'] == node['ablecube']:
            continue
        checked = remote(peer['ip'], 'probe', {'compatibility': peer['kind'] == 'host'})
        results.append(peer['hostname'] + ': 접속 확인')
    if not offline:
        remote(node['ablecube'], 'probe', {'node': node, 'compatibility': True, 'removing': not adding, 'joining': adding})
        results.append(node['hostname'] + ': 호스트명·관리 IP·HPN IP·VM 없음 확인')
    if adding:
        source_bundle(config, node)
        results.append('기존 SSH 키·Ceph 설정·libvirt secret 확인')
    return results


def execute_operation(operation):
    path = STATE / ('operation-' + operation['id'] + '.json')
    node = operation['node']
    config = operation['config']
    # Retry reapplies preparation (including SSH) and every peer sync from the start.
    # A removed target has already revoked SSH access, so its finished reset cannot
    # be repeated remotely; keep only that irreversible completion marker.
    reset_complete = operation['action'] == 'remove' and 'cleanup' in operation.get('done', [])
    operation['state'] = 'pending'
    operation['done'] = ['cleanup'] if reset_complete else []
    operation['messages'] = []
    operation['errors'] = []
    save_json(path, operation)
    def step(key, label, action):
        if key == 'cleanup' and reset_complete:
            operation['messages'].append('대상 호스트 내부 초기화는 이미 완료되었습니다.')
            return True
        try:
            action()
            operation['done'].append(key)
            operation['messages'].append(label)
            save_json(path, operation)
            return True
        except Exception as error:
            operation['errors'].append({'step': label, 'message': str(error)})
            save_json(path, operation)
            return False
    if operation['action'] == 'add':
        if not step('prepare', '신규 노드 준비', lambda: remote(node['ablecube'], 'prepare', source_bundle(config, node))):
            return operation
    # For removal cleanup first; never revoke access while VM definitions remain.
    elif not operation['offline']:
        if not step('cleanup', '대상 호스트 내부 설정 정리', lambda: remote(node['ablecube'], 'cleanup', {'node': node})):
            return operation
    for peer in participants(config):
        payload = {'config': config, 'base': operation['base'], 'kind': peer['kind']}
        if operation['action'] == 'add' and peer['ip'] == node['ablecube']:
            payload['kind'] = 'new'
        if operation['action'] == 'remove':
            payload['removed'] = [node['hostname'], node['ablecube'], node['ablecubePn'], 'pn-ablecube' + node['index']]
        if not step('sync:' + peer['ip'], peer['hostname'] + ' 설정 동기화', lambda peer=peer, payload=payload: remote(peer['ip'], 'sync', payload)):
            return operation
    if not operation['errors']:
        operation['state'] = 'complete'
        if operation.get('offline'):
            operation['messages'].append('등록 제거 완료. 대상 호스트 내부 정리는 수행되지 않았습니다. 재연결 전 정리가 필요합니다.')
    save_json(path, operation)
    return operation


def join_action(data):
    """A fresh host delegates enrollment without installing an uploaded config."""
    action = data.get('action')
    if action not in ('list', 'preflight-add', 'add', 'retry'):
        raise ValueError('지원하지 않는 추가 작업입니다.')
    current = read_json(CONFIG, {'clusterConfig': {'hosts': []}})
    manifest = read_json(MANIFEST, {})
    if current.get('clusterConfig', {}).get('hosts') and not is_compute(local_host(current) or {}):
        raise ValueError('신규 컴퓨팅 호스트에서 실행하십시오.')
    if action in ('preflight-add', 'add'):
        probe(data.get('payload'), compatibility=True)
    config = data.get('config', {})
    cluster = config.get('clusterConfig', {})
    if cluster.get('type') != HCI:
        raise ValueError('기존 ABLESTACK HCI cluster.json을 선택하십시오.')
    coordinator = next((h for h in cluster.get('hosts', []) if not is_compute(h)), None)
    if not coordinator or coordinator.get('ablecube') in local_addresses():
        raise ValueError('기존 HCI 호스트가 있는 cluster.json을 선택하십시오.')
    payload = {'action': action, 'config': config, 'payload': data.get('payload', {})}
    # Use the imported identity only for this connection; enrollment owns persistent changes.
    identity = data.get('privateKey')
    if identity:
        with tempfile.TemporaryDirectory(prefix='compute-join-') as directory:
            path = Path(directory) / 'id_rsa'
            atomic_write(path, identity.rstrip() + '\n')
            return remote(coordinator['ablecube'], 'join-coordinate', payload, identity=path)
    return remote(coordinator['ablecube'], 'join-coordinate', payload)


def public_action(action, data):
    if action == 'join':
        return join_action(data)
    config = read_json(CONFIG)
    host = local_host(config)
    coordinator = next((h for h in config['clusterConfig']['hosts'] if not is_compute(h)), None)
    # A single coordinator serializes operations even when different Cockpit hosts are used.
    if config['clusterConfig']['type'] == HCI and coordinator and host and not same_host(coordinator['hostname'], socket.gethostname()):
        # The established SSH session survives resetting the initiating compute host.
        # All subsequent peer connections use the coordinator's own, retained key.
        result = remote(coordinator['ablecube'], 'coordinate', {'action': action, 'payload': data})
        if isinstance(result, dict):
            result['coordinator'] = {'hostname': coordinator['hostname'], 'ip': coordinator['ablecube']}
            current = read_json(CONFIG, {'clusterConfig': {'hosts': []}})
            result['callerReset'] = is_compute(host) and local_host(current) is None
        return result
    if action == 'list':
        value = inventory(config)
        value['coordinator'] = {'hostname': coordinator['hostname'], 'ip': coordinator['ablecube']} if coordinator else None
        for field in ('operations', 'cleanupPending'):
            value[field] = [{k: v for k, v in item.items() if k not in ('base', 'config')} for item in value[field]]
        return value
    require_coordinator(config)
    pending = [o for o in inventory(config)['operations'] if o['state'] != 'complete']
    if action == 'cleanup-offline':
        if not re.fullmatch(r'[0-9a-f]{32}', str(data.get('id', ''))):
            raise ValueError('유효하지 않은 작업 ID입니다.')
        operation = read_json(STATE / ('operation-' + data['id'] + '.json'))
        if not (operation['action'] == 'remove' and operation.get('offline') and operation['state'] == 'complete'):
            raise ValueError('오프라인 제거 후 내부 정리가 남은 작업만 처리할 수 있습니다.')
        if any(h['hostname'] == operation['node']['hostname'] for h in config['clusterConfig']['hosts']):
            raise ValueError('다시 등록된 호스트는 이전 제거 기록으로 정리할 수 없습니다.')
        if not operation.get('cleanupDone'):
            remote(operation['node']['ablecube'], 'cleanup', {'node': operation['node']})
            operation['cleanupDone'] = True
            operation['messages'].append('오프라인 제거 대상 호스트 내부 정리 완료')
            save_json(STATE / ('operation-' + operation['id'] + '.json'), operation)
        return operation
    if action == 'retry':
        if not re.fullmatch(r'[0-9a-f]{32}', str(data.get('id', ''))):
            raise ValueError('유효하지 않은 작업 ID입니다.')
        operation = read_json(STATE / ('operation-' + data['id'] + '.json'))
        if operation['state'] == 'complete':
            return operation
        return execute_operation(operation)
    if pending:
        raise ValueError('진행 중인 작업이 있습니다. 해당 작업을 먼저 재시도하십시오.')
    adding = action in ('preflight-add', 'add')
    if adding:
        for path in STATE.glob('operation-*.json'):
            previous = read_json(path)
            if previous.get('offline') and not previous.get('cleanupDone') and (same_host(previous['node']['hostname'], str(data.get('hostname', ''))) or previous['node']['ablecube'] == data.get('ablecube') or previous['node']['ablecubePn'] == data.get('ablecubePn')):
                raise ValueError('오프라인 제거 이력이 있습니다. 제거 화면에서 대상 호스트 내부 정리를 완료한 뒤 다시 등록하십시오.')
        node = validate_node(data, config)
        offline = False
    else:
        node = assert_compute_target(config, data.get('hostname'))
        offline = data.get('offline') is True
        if not data.get('moldReleased') or (offline and not data.get('isolated')):
            raise ValueError('Mold의 VM·로컬 디스크 정리 및 호스트 등록 해제를 확인하십시오. 오프라인 제거는 전원 차단/격리 확인도 필요합니다.')
    results = preflight(config, node, adding, offline)
    if action.startswith('preflight-'):
        return {'node': node, 'checks': results}
    desired = copy.deepcopy(config)
    if adding:
        match = next((i for i, host in enumerate(desired['clusterConfig']['hosts']) if same_host(host['hostname'], node['hostname'])), None)
        if match is None:
            desired['clusterConfig']['hosts'].append(node)
        else:
            desired['clusterConfig']['hosts'][match] = node
    else:
        desired['clusterConfig']['hosts'] = [h for h in desired['clusterConfig']['hosts'] if h['hostname'] != node['hostname']]
    operation = {'id': uuid.uuid4().hex, 'action': 'add' if adding else 'remove', 'node': node, 'base': config, 'config': desired, 'offline': offline, 'state': 'pending', 'done': [], 'messages': [], 'errors': []}
    return execute_operation(operation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['list', 'join', 'preflight-add', 'add', 'preflight-remove', 'remove', 'retry', 'cleanup-offline', '_remote'])
    parser.add_argument('remote_action', nargs='?')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError('root 권한이 필요합니다.')
        data = json.load(sys.stdin) if args.action != 'list' else {}
        STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(STATE, 0o700)
        # Separate remote-file lock from the coordinator lock (local calls are direct).
        name = 'remote.lock' if args.action == '_remote' and args.remote_action not in ('coordinate', 'join-coordinate') else 'coordinator.lock'
        with (STATE / name).open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = remote_action(args.remote_action, data) if args.action == '_remote' else public_action(args.action, data)
        # Operation snapshots are private on disk; never expose base/config in UI.
        if isinstance(result, dict) and 'done' in result:
            result = {k: v for k, v in result.items() if k not in ('base', 'config')}
        code = 207 if isinstance(result, dict) and result.get('errors') else 200
        print(json.dumps({'code': code, 'val': result}, ensure_ascii=False))
    except Exception as error:
        print(json.dumps({'code': 500, 'val': str(error)}, ensure_ascii=False))


if __name__ == '__main__':
    main()

"""Bounded measured collection. No arbitrary endpoints, seeds or main roles."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import os
import platform
import random
import socket
import struct
import sys
import threading
import time
import uuid

from . import __version__
from .config import PURPOSE, object_map, planned, source_hashes, sha
from .protocol import Process, adu, parse, recv_adu
from .recorder import Capture, JsonLines
from .scenarios import build
from .validation import save, validate

HOST, PORT = '127.0.0.1', 15020


class Server:
    def __init__(self, mapping, audit, steps, connection_id):
        self.state = Process(mapping)
        self.audit, self.steps, self.connection_id = audit, steps, connection_id
        self.errors = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((HOST, PORT))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        try:
            conn, peer = self.listener.accept()
            with conn:
                conn.settimeout(10)
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                t = 0
                while True:
                    try:
                        incoming = recv_adu(conn)
                    except EOFError:
                        break
                    tid, pdu = parse(incoming)
                    step = self.steps[t]
                    if pdu.hex() != step['pdu_hex']:
                        raise ValueError('Received operation differs from planned transaction')
                    before = self.state.snapshot()
                    expected = adu(tid, self.state.handle(pdu))
                    wire = expected
                    if step['intervention'] == 'response_injection':
                        if pdu[0] != 3 or int.from_bytes(pdu[1:3], 'big') != self.state.mapping['setpoint_register']:
                            raise ValueError('Only a setpoint read can be altered')
                        wire = adu(tid, b'\x03\x02' + struct.pack('!H', step['replacement']))
                        if wire == expected:
                            raise ValueError('No-op response mutation prohibited')
                    record = dict(transaction_index=t, connection_id=self.connection_id, tid=tid, unit=1,
                                  request_adu_hex=incoming.hex(), expected_response_adu_hex=expected.hex(),
                                  wire_response_adu_hex=wire.hex(), response_overridden=wire != expected,
                                  peer_ip=peer[0], peer_port=peer[1], server_observed_at_ns=time.time_ns(),
                                  **{k + '_before': v for k, v in before.items()},
                                  **{k + '_after': v for k, v in self.state.snapshot().items()})
                    self.audit.append(record)
                    conn.sendall(wire)
                    t += 1
                if t != len(self.steps):
                    raise ValueError('Connection ended before all planned transactions')
        except Exception as exc:
            self.errors.append(f'{type(exc).__name__}: {exc}')
        finally:
            self.listener.close()

    def finish(self):
        self.thread.join(timeout=12)
        if self.thread.is_alive() or self.errors:
            raise RuntimeError('; '.join(self.errors) or 'Server did not finish')


def run(output, run_id):
    config = planned(run_id)  # rejects main roles before any write/socket/capture
    if os.environ.get('C3QUAL_ISOLATED_DOCKER') != '1' or platform.system() != 'Linux':
        raise RuntimeError('Use the supplied isolated Docker launcher; host collection disabled')
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise RuntimeError('Expected network_mode:none with only loopback')
    episodes = build(config['seed'], config['map'], config['values'], config['schedule'])
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    recording = f'{run_id}-{timestamp}-{uuid.uuid4().hex[:8]}'
    folder = Path(output) / recording
    folder.mkdir(parents=True, exist_ok=False)
    connection_id = recording + ':connection-0'
    manifest = dict(schema_version=2, version=__version__, purpose=PURPOSE, run_id=recording,
                    planned_run=config, connection_id=connection_id, status='STARTED', capture_required=True,
                    python=sys.version, platform=platform.platform(), created_at_utc=timestamp,
                    isolation='docker-network-none', server_host=HOST, server_port=PORT,
                    episodes=len(episodes), source_sha256=source_hashes(),
                    timing='Application send-start and receive-complete use time.time_ns; capture records kernel timestamps',
                    no_model_preprocessing_or_training=True, academic_approval_asserted=False)
    save(folder / 'run_manifest.json', manifest)
    save(folder / 'planned_run.json', config)
    save(folder / 'scenario_plan.json', episodes)
    ledger = JsonLines(folder / 'application_ledger.jsonl')
    oracle = JsonLines(folder / 'server_audit.jsonl')
    hooks = JsonLines(folder / 'intervention_audit.jsonl')
    capture = server = None
    offsets = dict(client_to_server=0, server_to_client=0)
    rng = random.Random(config['seed'] ^ 0xc302)
    tid = rng.randrange(65536)
    rows = []
    error = None
    try:
        capture = Capture(folder)
        steps = [step for ep in episodes for step in ep['steps']]
        server = Server(object_map(config['map']), oracle, steps, connection_id)
        server.thread.start()
        with socket.create_connection((HOST, PORT), timeout=5) as client:
            client.settimeout(10)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            local_port = client.getsockname()[1]
            manifest['client_port'] = local_port
            t = 0
            for ep in episodes:
                for step in ep['steps']:
                    tid = (tid + 1) & 65535
                    outgoing = adu(tid, bytes.fromhex(step['pdu_hex']))
                    time.sleep(rng.uniform(0.008, 0.015))  # same distribution for all classes
                    hooks.append(dict(transaction_index=t, connection_id=connection_id,
                                      request_adu_hex=outgoing.hex(), kind=step['intervention'],
                                      replacement=step['replacement'], recorded_at_ns=time.time_ns(),
                                      use='PRIVATE_ANNOTATION_EVIDENCE_NOT_PREDICTORS'))
                    sent_at = time.time_ns()
                    client.sendall(outgoing)
                    incoming = recv_adu(client)
                    received_at = time.time_ns()
                    if parse(incoming)[0] != tid:
                        raise ValueError('Response TID differs')
                    for j, (role, direction, raw, stamp) in enumerate((
                            ('request', 'client_to_server', outgoing, sent_at),
                            ('response', 'server_to_client', incoming, received_at))):
                        label = 'command_injection' if j == 0 and step['intervention'] == 'command_injection' else \
                                'response_injection' if j == 1 and step['intervention'] == 'response_injection' else 'normal'
                        row = dict(event_id=f'{recording}:e{len(rows)}', run_id=recording, connection_id=connection_id,
                                   transaction_index=t, episode_id=ep['episode_id'], scenario=ep['family'],
                                   step=step['step'], label=label, role=role, direction=direction, tid=tid, unit=1,
                                   adu_hex=raw.hex(), pdu_hex=raw[7:].hex(), stream_offset=offsets[direction],
                                   observed_at_ns=stamp, source_ip=HOST, destination_ip=HOST,
                                   source_port=local_port if j == 0 else PORT,
                                   destination_port=PORT if j == 0 else local_port,
                                   metadata_use='AUDIT_ONLY_NOT_MODEL_INPUTS')
                        offsets[direction] += len(raw)
                        rows.append(row)
                        ledger.append(row)
                    t += 1
        server.finish()
        manifest['status'] = 'CAPTURE_COLLECTED'
    except Exception as exc:
        error = exc
        manifest.update(status='FAILED', error=f'{type(exc).__name__}: {exc}')
    finally:
        if capture:
            manifest['capture_exit_code'] = capture.stop()
        if server and server.thread.is_alive():
            server.thread.join(timeout=12)
        for f in (ledger, oracle, hooks):
            f.close()
        manifest['observed_application_messages'] = len(rows)
        manifest['proposed_label_counts_not_yet_verified'] = dict(Counter(r['label'] for r in rows))
        manifest['input_sha256'] = {p.name: sha(p) for p in folder.iterdir()
                                    if p.is_file() and p.name != 'run_manifest.json'}
        save(folder / 'run_manifest.json', manifest)
    if error:
        raise RuntimeError(f'Failed run preserved at {folder}: {error}') from error
    report = validate(folder)
    if report['status'] != 'PASSED':
        raise RuntimeError(f'Validation failed; evidence preserved at {folder}: {report["errors"]}')
    return folder, report

# Remember earlier wire messages, build allowed features, and apply frozen models.
"""v2 label-free complete-ADU inference adapter. Experimental engineering version.

Consumes ordered, reassembled wire observations from a trusted transport adapter.
Does not implement live capture/TCP reassembly and does not establish authenticity
of anchors. The supported threat model has one writer/outstanding request, unit 1.
The original v1 implementation and models remain untouched.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

VERSION = 'c3-stream-v2-20261025'
HERE = Path(__file__).resolve().parent
LOCKED = HERE/'locked/v1_20261025'
sys.path.insert(0,str(LOCKED))
from c3model.records import decode, CURRENT, CONTEXT, WIRE

NAN = float('nan')

# Keep connection state and turn ordered public messages into model features.
class Detector:
    """One detector per public map; no simulator transaction/episode IDs used."""
    # Require the declared trust policy and start with empty connection history.
    def __init__(self, mapping, *, trusted_single_writer=False):
        if trusted_single_writer is not True:
            raise ValueError('This adapter requires the declared trusted-anchor/single-writer testbed contract')
        self.connections = {}
        self.set_map(mapping)

    # Validate the public addresses and clear context because the address meanings have changed.
    def set_map(self,mapping):
        keys = ('mode_register','setpoint_register','pump_coil')
        if not all(type(mapping.get(k)) is int and 0 <= mapping[k] <= 65535 for k in keys):
            raise ValueError('Public map must contain valid integer addresses')
        if mapping['mode_register'] == mapping['setpoint_register']:
            raise ValueError('Mode and setpoint register roles must be distinct')
        self.mapping = {k:mapping[k] for k in keys}
        self.connections.clear()  # Explicit public configuration boundary.

    # Start a connection with no mode, setpoint, pending request, or consumed bytes.
    @staticmethod
    def fresh():
        return {'ordinal':0,'mode':None,'setpoint':None,'pending':None,
                'offsets':{'client_to_server':0,'server_to_client':0}}

    # Discard this connection's remembered history after transport or trust is lost.
    def invalidate(self,connection):
        """Transport must call this on loss, reconnect, timeout, or trust loss."""
        self.connections.pop(connection,None)

    # Decide using the current message and existing history before updating state for later messages.
    def observe(self,row):
        connection = row.get('connection_id')
        base = {'schema_version':2,'adapter_version':VERSION,'event_id':row.get('event_id'),
                'observed_at_ns':row.get('observed_at_ns'),'eligible':None,'context_available':False,
                'prediction':None,'processing_status':'invalid_input','evidence':{},'features':None}
        if not isinstance(connection,str) or not connection:
            base['reason'] = 'Missing transport connection generation'; return base
        if not isinstance(row.get('event_id'),str) or not row['event_id'] or type(row.get('observed_at_ns')) is not int:
            self.invalidate(connection)
            base['reason'] = 'Event ID and integer observation timestamp are required'; return base
        state = self.connections.setdefault(connection,self.fresh())
        # Clear unsafe state and return an explicit failure status instead of a normal prediction.
        def fail(reason,status='invalid_input'):
            self.invalidate(connection)
            base.update(processing_status=status,reason=reason)
            return base
        direction = row.get('direction')
        if direction not in ('client_to_server','server_to_client'):
            return fail('Missing/invalid transport direction')
        request = direction == 'client_to_server'
        try:
            raw = bytes.fromhex(row['adu_hex'])
            decoded = decode(raw,request)
        except (KeyError,ValueError,TypeError) as exc:
            return fail(str(exc))
        if decoded['unit'] != 1:
            return fail('Only unit 1 is qualified; cross-unit context forbidden','unsupported_input')
        offset = row.get('stream_offset')
        if type(offset) is not int or offset != state['offsets'][direction]:
            return fail('Missing/noncontiguous stream bytes; anchors invalidated','stream_gap')
        state['offsets'][direction] += len(raw)
        ordinal = state['ordinal']; state['ordinal'] += 1
        fc, addr, word = decoded['function'],decoded['address'],decoded['word']
        m=self.mapping
        role = ('pump' if fc in (1,5) and addr == m['pump_coil'] else
                'mode' if fc in (3,6) and addr == m['mode_register'] else
                'setpoint' if fc in (3,6) and addr == m['setpoint_register'] else None) if request else None
        if request and (role is None or (fc == 6 and role == 'mode' and word not in (0,1))):
            return fail('Operation outside declared public map/policy','unsupported_input')
        # Pair with the outstanding request; a reused TID alone is not a transaction identity.
        pending = state['pending']
        if request and pending is not None:
            return fail('Concurrent outstanding request; identity ambiguous','ambiguous_pair')
        pair_role = None
        if not request:
            if pending is None:
                return fail('Response without an observed request','unmatched_response')
            previous = pending['decoded']
            if (decoded['tid'],decoded['unit'],fc) != (previous['tid'],previous['unit'],previous['function']):
                return fail('Response TID/unit/function does not match pending request','pair_mismatch')
            if fc in (5,6) and not decoded['exception'] and decoded['pdu'] != previous['pdu']:
                return fail('Write acknowledgement differs from request','pair_mismatch')
            pair_role = pending['role']
            if fc == 3 and pair_role == 'mode' and not decoded['exception'] and word not in (0,1):
                return fail('Mode outside declared public policy','unsupported_input')
        # Public function/address policy selects the task; ground-truth labels do not select it.
        task = ('command' if request and fc == 5 and word == 0xff00 else
                'response' if not request and fc == 3 and pair_role == 'setpoint' and not decoded['exception'] else '')
        # Use an earlier observation only while it is within the allowed message-distance limit.
        def anchor(key):
            item=state[key]
            return item if item is not None and 0 <= ordinal-item['ordinal']-1 <= 6 else None
        mode, setpoint = anchor('mode'),anchor('setpoint')
        chosen = mode if task == 'command' else setpoint if task == 'response' else None
        available = chosen is not None
        rule = 'out_of_scope' if not task else 'abstain'
        if task and available:
            rule = ('command_injection' if mode['value'] == 0 else 'normal') if task == 'command' else (
                    'response_injection' if word != setpoint['value'] else 'normal')
        codes={'mode':1,'setpoint':2,'pump':3}
        number=lambda value: NAN if value is None else value
        try:
            ip=lambda name: NAN if row.get(name) is None else int(ipaddress.ip_address(row[name]))
            # Keep absent wire fields as NaN; a real zero remains a real zero.
            features={
                'current_function':fc,'current_unit':decoded['unit'],'current_is_request':int(request),
                'current_pdu_length':decoded['pdu_length'],'current_wire_address':number(addr),
                'current_wire_word':number(word),'current_wire_quantity':number(decoded['quantity']),
                'current_byte_count':number(decoded['byte_count']),
                'current_request_object_role':codes.get(role,0) if request else NAN,
                'current_numeric_tid':decoded['tid'],'current_source_ip':ip('source_ip'),
                'current_destination_ip':ip('destination_ip'),'current_source_port':number(row.get('source_port')),
                'current_destination_port':number(row.get('destination_port')),
                'earlier_observed_mode':mode['value'] if mode else NAN,
                'earlier_acknowledged_setpoint':setpoint['value'] if setpoint else NAN,
                'paired_request_object_role':codes.get(pair_role,0) if not request else NAN,
                'response_minus_acknowledged_setpoint':word-setpoint['value'] if task == 'response' and setpoint else NAN,
                'context_available':available}
        except (ValueError,TypeError) as exc:
            return fail(str(exc))
        # Keep public eligibility, usable history, and the prediction status as separate fields.
        base.update(eligible=bool(task),context_available=available,task=task,prediction=rule,features=features,
                    function_code=fc,wire_address=addr,
                    address_or_register=addr if request else pending['decoded']['address'],
                    address_origin='current_wire' if request or fc in (5,6) else 'earlier_paired_request',
                    preprocessing_version=VERSION,
                    processing_status='out_of_scope' if not task else 'complete' if available else 'insufficient_context',
                    evidence={'paired_request_event_id':pending['event_id'] if not request else None,
                              'mode_anchor_event_id':mode['event_id'] if mode else None,
                              'setpoint_anchor_event_id':setpoint['event_id'] if setpoint else None,
                              'rule_prediction':rule,'kind':'observed_policy_context_not_RF_attribution'})
        # No current write/ACK updates may affect the decision just constructed.
        if request:
            if fc == 6 and role in ('mode','setpoint'): state[role]=None
            state['pending']={'decoded':decoded,'role':role,'event_id':row.get('event_id')}
        else:
            state['pending']=None
            if not decoded['exception']:
                if fc == 3 and pair_role == 'mode':
                    state['mode']={'value':word,'ordinal':ordinal,'event_id':row.get('event_id')}
                elif fc == 6 and pair_role == 'setpoint':
                    state['setpoint']={'value':word,'ordinal':ordinal,'event_id':row.get('event_id')}
        return base

# Verify the lock, original code, model bytes, and feature order before loading saved models.
def load_locked_models(artifacts=None):
    """Hash-check locally trusted models BEFORE deserialization. No fitting."""
    import joblib
    artifacts=Path(artifacts or LOCKED/'artifacts')
    lock=json.loads((artifacts/'experiment_lock.json').read_text(encoding='utf-8-sig'))
    # Calculate a file hash for an integrity comparison.
    def digest(path):
        with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()
    if digest(artifacts/'experiment_lock.json') != 'f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9':
        raise ValueError('Unexpected experiment lock identity')
    for name,expected in lock['code_sha256'].items():
        if digest(LOCKED/'c3model'/name) != expected: raise ValueError('Locked decoder/model code changed')
    models={}
    for name,columns in lock['methods'].items():
        path=artifacts/'models'/f'{name}.joblib'
        if digest(path) != lock['artifact_sha256'][f'models/{name}.joblib']:
            raise ValueError('Model hash mismatch: '+name)
        model=joblib.load(path)
        if list(model.feature_names_in_) != columns: raise ValueError('Saved feature schema mismatch')
        models[name]=model
    return models

# Select supported rows and apply saved preprocessing and RF without fitting anything.
def predict_batch(observations,models,method='D'):
    """Apply the original saved imputer/RF; never fit a replacement transform.

    Confidence is an uncalibrated RF probability. Reasons are observed policy
    evidence, not SHAP attribution or proof of malicious intent.
    """
    import pandas as pd
    from c3model.experiment import METHODS,feature_frame
    if method not in METHODS: raise ValueError('Unknown method')
    result=[{k:v for k,v in row.items() if k != 'features'} for row in observations]
    # Contextual models abstain before imputation if their earlier anchors are unavailable.
    indices=[i for i,r in enumerate(observations) if r.get('eligible') is True and r.get('features') is not None
             and (not method.startswith('D') or r['context_available'])]
    for item in result:
        item.update(model_version='locked-v1-20261025/'+method,confidence=None,
                    confidence_kind='uncalibrated_RF_probability',decision_timestamp=datetime.now(timezone.utc).isoformat())
        # Never accidentally emit a rule prediction under an RF method name.
        item['prediction']='out_of_scope' if item['eligible'] is False else 'abstain'
    if indices:
        frame=pd.DataFrame([observations[i]['features'] for i in indices])
        if method.endswith('wire') and frame[WIRE].isna().any().any():
            raise ValueError('Wire model requires all endpoint/header fields')
        # Use the saved feature allowlist and ordering, not the incoming dictionary order.
        x=feature_frame(frame,METHODS[method])
        labels=models[method].predict(x); probabilities=models[method].predict_proba(x)
        for i,label,probability in zip(indices,labels,probabilities,strict=True):
            result[i].update(prediction=str(label),confidence=float(max(probability)),processing_status='complete')
    return result

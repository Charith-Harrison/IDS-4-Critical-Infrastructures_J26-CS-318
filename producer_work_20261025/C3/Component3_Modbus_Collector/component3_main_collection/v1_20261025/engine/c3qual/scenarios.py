"""Compile the adopted engineering controls; no model features or windows."""
import hashlib
import itertools
import random
from .config import design,object_map
from .protocol import req


def channel_seed(seed,channel):
    return int.from_bytes(hashlib.sha256(f'{seed}:{channel}'.encode()).digest()[:8],'big')


def build(config):
    d=design()
    m=object_map(config['map'])
    bounds=next(v for v in d['collection_factors']['value_profiles'] if v['id']==config['values'])
    values=random.Random(channel_seed(config['seed'],'values'))
    schedule=random.Random(channel_seed(config['seed'],'schedule'))
    episodes=[]
    normal_only=config['recording_mode']=='normal_only'
    for block,(tid_profile,q) in enumerate(itertools.product(config['tid_profiles'],config['anchor_poll_counts'])):
        a,b=values.sample(range(bounds['minimum'],bounds['maximum']+1),2)
        for family in [s['id'] for s in d['scenarios']]:
            variants=['a_to_b','b_to_a'] if family=='R_CHANGED_READBACK' else \
                     ['a','b'] if family=='N_GENUINE_READBACK' else ['default']
            for variant in variants:
                actual,reported=(b,a) if variant=='b_to_a' else (a,b)
                if variant=='b':
                    actual=b
                mode=0 if family in ('C_BLOCKED_ON','N_INHIBITED_IDLE') else 1
                if family=='N_AUTHORIZED_UPDATE':
                    mode=block%2
                if normal_only and family=='C_BLOCKED_ON':
                    mode=1
                name='N_C_TEMPLATE_CONTROL' if normal_only and family=='C_BLOCKED_ON' else \
                     'N_R_TEMPLATE_CONTROL' if normal_only and family=='R_CHANGED_READBACK' else family
                steps=[]
                def add(step,fc,addr,word,intervention='none',replacement=None,decision=None):
                    steps.append(dict(step=step,pdu_hex=req(fc,addr,word).hex(),intervention=intervention,
                                      replacement=replacement,decision_task=decision))
                def poll(step='gap_poll'):
                    # A mode read here would refresh the very anchor being aged.
                    add(step,1,m['pump_coil'],1)
                def polls():
                    for _ in range(q): poll()
                for _ in range(schedule.randrange(3)):
                    poll('prefix_poll')
                templates=d['ordering_compiler_spec']['canonical_templates'][config['ordering']]
                template_index=schedule.randrange(len(templates))
                template=templates[template_index]
                for token in template:
                    if token=='WM':
                        if family=='N_MODE_TRANSITION':
                            add('transition_to_0',6,m['mode_register'],0)
                            add('observe_transition_0',3,m['mode_register'],1)
                            add('off_in_mode_0',5,m['pump_coil'],0)
                        add('set_mode',6,m['mode_register'],mode)
                    elif token in ('WS','WS_refresh'):
                        add('set_setpoint' if token=='WS' else 'refresh_setpoint',6,m['setpoint_register'],actual)
                        if token=='WS' and family=='N_AUTHORIZED_UPDATE':
                            actual=b
                            add('authorized_update',6,m['setpoint_register'],actual)
                        if token=='WS' and family=='N_REPEAT_WRITE':
                            add('repeat_setpoint',6,m['setpoint_register'],actual)
                    elif token in ('RM','RM_pre','RM_refresh'):
                        add('observe_mode' if token=='RM' else token.lower(),3,m['mode_register'],1)
                    elif token=='RS':
                        # Refresh only when intervening work would defeat the exact q contract.
                        if steps[-1]['pdu_hex'][:6] != req(6,m['setpoint_register'],actual).hex()[:6]:
                            add('refresh_setpoint_for_read',6,m['setpoint_register'],actual)
                        polls()
                        mutate=family=='R_CHANGED_READBACK' and not normal_only
                        add('readback_target',3,m['setpoint_register'],1,
                            'response_injection' if mutate else 'none',reported if mutate else None,'readback')
                    elif token=='ON':
                        if family=='N_INHIBITED_IDLE' or family=='N_AUTHORIZED_UPDATE' and mode==0:
                            continue
                        if steps[-1]['pdu_hex']!=req(3,m['mode_register'],1).hex():
                            add('refresh_mode_for_on',3,m['mode_register'],1)
                        polls()
                        add('pump_on',5,m['pump_coil'],0xff00,
                            'command_injection' if family=='C_BLOCKED_ON' and not normal_only else 'none',
                            decision='on')
                        if family=='N_REPEAT_WRITE':
                            add('refresh_mode_for_repeat',3,m['mode_register'],1)
                            polls()
                            add('repeat_on',5,m['pump_coil'],0xff00,decision='on')
                    elif token=='RC':
                        add('observe_coil',1,m['pump_coil'],1)
                    elif token in ('OFF_setup','OFF_restore'):
                        add(token.lower(),5,m['pump_coil'],0)
                        if token=='OFF_restore' and family=='N_REPEAT_WRITE':
                            add('repeat_off',5,m['pump_coil'],0)
                        if token=='OFF_restore' and family=='N_MODE_TRANSITION':
                            add('transition_back_0',6,m['mode_register'],0)
                            add('observe_transition_back_0',3,m['mode_register'],1)
                    elif token=='RS_recovery':
                        add('recovery_read',3,m['setpoint_register'],1)
                    else:
                        raise ValueError('Unknown transaction token '+token)
                episodes.append(dict(family=name,template_family=family,variant=variant,block=block,
                                     tid_profile=tid_profile,anchor_poll_count=q,a=a,b=b,
                                     template_id=f'{config["ordering"]}:{template_index}',steps=steps))
    if len(episodes)!=90:
        raise ValueError('Nine crossed blocks must yield 90 episodes')
    schedule.shuffle(episodes)
    tid_random=random.Random(channel_seed(config['seed'],'tid_random'))
    tid_seq=random.Random(channel_seed(config['seed'],'tid_sequence')).randrange(65536)
    delays=random.Random(channel_seed(config['seed'],'delays'))
    timing=next(t for t in d['collection_factors']['timing'] if t['id']==config['timing'])['interexchange_delay_ms']
    for i,ep in enumerate(episodes):
        ep['episode_id']=f'episode-{i:03d}'
        for step in ep['steps']:
            if ep['tid_profile']=='DSEQ':
                tid_seq=(tid_seq+1)&65535
                tid=tid_seq
            elif ep['tid_profile']=='DREUSE': tid=5
            else: tid=tid_random.randrange(65536)
            step.update(tid=tid,sleep_seconds=delays.uniform(*timing)/1000)
    return episodes

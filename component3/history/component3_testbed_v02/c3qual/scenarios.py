"""Prospective scenarios; private scenario/step fields are never model inputs."""
import random
from .config import design, object_map
from .protocol import req


def build(seed, map_id='M0', values='V0', schedule='S1'):
    d = design()
    m = object_map(map_id)
    v = next(v for v in d['value_profiles'] if v['id'] == values)
    if schedule not in ('S0', 'S1', 'S2'):
        raise ValueError('Unknown schedule')
    rng = random.Random(seed)
    episodes = []
    families = [s['id'] for s in d['scenarios']]
    for block in range(2):
        a, b = rng.sample(range(v['minimum'], v['maximum'] + 1), 2)
        for family in families:
            variants = ['a_to_b', 'b_to_a'] if family == 'R_CHANGED_READBACK' else \
                       ['a', 'b'] if family == 'N_GENUINE_READBACK' else ['default']
            for variant in variants:
                mode = 0 if family in ('C_BLOCKED_ON', 'N_INHIBITED_IDLE') else 1
                if family == 'N_AUTHORIZED_UPDATE':
                    mode = block % 2  # lawful setpoint updates in BOTH modes
                actual, reported = (b, a) if variant == 'b_to_a' else (a, b)
                if variant == 'b':
                    actual = b
                steps = []
                def add(name, fc, addr, word, intervention='none', replacement=None):
                    steps.append(dict(step=name, pdu_hex=req(fc, addr, word).hex(),
                                      intervention=intervention, replacement=replacement))
                def poll():
                    fc = rng.choice((1, 3))
                    addr = m['pump_coil'] if fc == 1 else m['mode_register']
                    add('benign_poll', fc, addr, 1)
                # Prefix lengths come from the same distribution in every family.
                # This occurs BEFORE visible anchors, so it cannot age them out.
                for _ in range(0 if schedule == 'S0' else rng.randrange(3)):
                    poll()
                add('set_mode', 6, m['mode_register'], mode)
                add('observe_mode', 3, m['mode_register'], 1)
                add('pump_off', 5, m['pump_coil'], 0)
                add('set_setpoint', 6, m['setpoint_register'], actual)
                if family == 'N_AUTHORIZED_UPDATE':
                    add('update_setpoint', 6, m['setpoint_register'], b)
                    actual = b
                if family == 'N_REPEAT_WRITE':
                    add('repeat_setpoint', 6, m['setpoint_register'], actual)
                if family == 'N_MODE_TRANSITION':
                    add('transition_to_0', 6, m['mode_register'], 0)
                    add('observe_mode_0', 3, m['mode_register'], 1)
                    add('off_while_inhibited', 5, m['pump_coil'], 0)
                    add('transition_to_1', 6, m['mode_register'], 1)
                if schedule == 'S2':
                    # Held-out legal ordering: coil read precedes readback, which
                    # precedes a refreshed mode anchor and the command decision.
                    add('observe_coil_early', 1, m['pump_coil'], 1)
                add('readback', 3, m['setpoint_register'], 1,
                    'response_injection' if family == 'R_CHANGED_READBACK' else 'none',
                    reported if family == 'R_CHANGED_READBACK' else None)
                # Fresh mode anchor after variable-length setup; no hidden reset.
                add('refresh_mode', 3, m['mode_register'], 1)
                if family != 'N_INHIBITED_IDLE' and not (family == 'N_AUTHORIZED_UPDATE' and mode == 0):
                    add('pump_on', 5, m['pump_coil'], 0xff00,
                        'command_injection' if family == 'C_BLOCKED_ON' else 'none')
                    if family == 'N_REPEAT_WRITE':
                        add('repeat_on', 5, m['pump_coil'], 0xff00)
                add('observe_coil', 1, m['pump_coil'], 1)
                add('restore_coil', 5, m['pump_coil'], 0)
                if family == 'N_REPEAT_WRITE':
                    add('repeat_off', 5, m['pump_coil'], 0)
                add('genuine_recovery_read', 3, m['setpoint_register'], 1)
                episodes.append(dict(family=family, variant=variant, block=block,
                                     a=a, b=b, steps=steps))
    rng.shuffle(episodes)
    for i, ep in enumerate(episodes):
        ep['episode_id'] = f'episode-{i:03d}'
    return episodes

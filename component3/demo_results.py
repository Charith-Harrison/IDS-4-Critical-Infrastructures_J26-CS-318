"""Read-only, human-readable views of existing saved experiment results."""
from pathlib import Path
from demo_data import HERE,LOCKED,read,sha

CONDITIONS={
    'Repeat conditions':'final_test_repeat',
    'New values':'final_test_values',
    'New public map':'final_test_map',
    'Changed ordering':'final_test_order',
    'Changed timing':'final_test_timing',
}
METHOD_NAMES={
    'A':'Protocol checks',
    'B':'Packet-only RF',
    'D':'Context-aware RF',
    'C':'Causal policy rules',
    'B-wire':'Packet-only RF + wire headers',
    'D-wire':'Context-aware RF + wire headers',
}

def load_results():
    audit=read(HERE/'reports/audit_final_20261025/audit.json')
    preservation=read(HERE/'reports/preservation.json')
    original=next(m for m in preservation['moves'] if m['after']=='component3/locked')['files']
    reports={}
    for role in CONDITIONS.values():
        relative=f'reports/locked_results/{role}_report.json'
        path=LOCKED/relative
        if sha(path) != original['v1_20261025/'+relative]['sha256']:
            raise ValueError('Saved result file changed: '+role)
        reports[role]=read(path)
    protocol_path=HERE/'history/component3_main_collection/v1_20261025/frozen/protocol.json'
    if sha(protocol_path) != '7634b3187e53c029db5d4755c6c3cf9df6a7985ab8ad1c67d3ebf00662a43c48':
        raise ValueError('Frozen scope configuration changed')
    environment_count=read(protocol_path)['grouping']['environment_count']
    return {'audit':audit,'conditions':reports,'environment_count':environment_count}

def comparison_rows(report,methods=('B','D')):
    """Same saved common cohort throughout; no pooling or model evaluation."""
    output=[]
    for method in methods:
        result=report['methods'][method]['common_cohort']
        matrix=result['confusion']; normal=sum(matrix[0])
        output.append({'Model':METHOD_NAMES[method],'Macro F1':result['macro_f1'],
                       'Command recall':result['per_class']['command_injection']['recall'],
                       'Response recall':result['per_class']['response_injection']['recall'],
                       'False-alarm rate':sum(matrix[0][1:])/normal if normal else None,
                       'Normal precision':result['per_class']['normal']['precision']})
    return output

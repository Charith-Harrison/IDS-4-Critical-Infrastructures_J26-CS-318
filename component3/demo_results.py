# Read saved experiment metrics for display without running another evaluation.
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

# Load existing result reports and their saved denominators.
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

# Format saved methods on the same supported cohort; do not pool new scores.
def comparison_rows(report,methods=('B','D'),*,evaluation='Common supported cohort'):
    """Same saved common cohort throughout; no pooling or model evaluation."""
    output=[]
    for method in methods:
        saved=report['methods'][method]
        result=saved['common_cohort']
        matrix=result['confusion']; normal=sum(matrix[0]) if matrix else 0
        support=result['support']
        # Divide by the saved cohort support, not only the cells represented in
        # the matrix. Any unrepresented decisions must not disappear from accuracy.
        represented=sum(sum(row) for row in matrix) if matrix else 0
        if represented>support:
            raise ValueError('Confusion matrix exceeds saved evaluation support')
        correct=sum(matrix[i][i] for i in range(len(matrix))) if matrix else None
        eligible=report['task_eligible']
        output.append({'Model':METHOD_NAMES[method],
                       'Accuracy (%)':100*correct/support if correct is not None and support else None,
                       'Macro F1':result['macro_f1'],
                       'Command recall':result['per_class']['command_injection']['recall'],
                       'Response recall':result['per_class']['response_injection']['recall'],
                       'False-alarm rate':sum(matrix[0][1:])/normal if normal else None,
                       'Normal precision':result['per_class']['normal']['precision'],
                       'Evaluated decisions':support,
                       'Prediction coverage (% eligible)':100*saved['scored']/eligible if eligible else None,
                       'Abstentions':saved['abstained'],
                       'Predictions produced':saved['scored'], 'Eligible decisions':eligible,
                       'Common cohort unscored':support-represented,
                       'Evaluation':evaluation, 'Accuracy cohort':'Common supported cohort'})
    return output


def comparison_export(conditions):
    """Export derived final metrics separately from the original saved reports."""
    rows=[]
    for condition,role in CONDITIONS.items():
        report=conditions[role]
        methods=('A','B','C','D','B-wire','D-wire')
        for method,row in zip(methods,comparison_rows(report,methods,evaluation='Final test · '+condition)):
            rows.append({'Method':method,**row})
    return rows

# Build the current research dashboard; visible examples and metrics come from saved evidence.
"""Component 3 research demo: saved comparisons with captured-byte evidence."""
from html import escape
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import pandas as pd
import streamlit as st
from demo_data import load_demo
from demo_results import CONDITIONS,comparison_rows,load_results
from runtime import CURRENT,CONTEXT
from traffic_ui import render_analyze_traffic

NAMES={'normal':'Normal','command_injection':'Command injection',
       'response_injection':'Response injection','abstain':'Abstain','out_of_scope':'Out of scope'}

st.set_page_config(page_title='TCP/MODBUS Attack Detection',page_icon='↔',layout='wide')
st.markdown('<style>'+ (HERE/'frontend.css').read_text(encoding='utf-8')+'</style>',unsafe_allow_html=True)
st.title('TCP/MODBUS Attack Detection')
st.markdown('<div class="component-subtitle"><strong>Command and Response Injection Detection</strong><span class="testbed-badge">Controlled Modbus/TCP testbed</span></div>',unsafe_allow_html=True)

# Cache the verified demonstration data for this dashboard session.
@st.cache_data(show_spinner='Loading captured examples…')
def demonstration(): return load_demo(saved_predictions_only=True)

# Cache the saved experiment reports used by the results page.
@st.cache_data(show_spinner=False)
def saved_results(): return load_results()

try:
    saved=saved_results()
except (OSError,ValueError,KeyError) as exc:
    st.error(f'Saved results are unavailable: {exc}')
    st.stop()
try:
    demo=demonstration()
    demo_error=None
except (OSError,ValueError,KeyError) as exc:
    demo=None
    demo_error=str(exc)

demo_tab,how_tab,results_tab,evidence_tab,scope_tab=st.tabs(['Demo','How it works','Results','Evidence','Dataset & scope'])

# Escape text before placing it inside dashboard HTML.
def text(value): return escape(str(value))

# Present fields actually carried by the current Modbus message.
def current_fields(case):
    f=case['decision']['features']
    valid='Yes' if case['annotation']['parse_state']=='parser_ok' else 'No'
    if case['decision']['task']=='command':
        return [('Function','Write Single Coil'),('Address',int(f['current_wire_address'])),
                ('Value','ON'),('Protocol valid',valid)]
    return [('Function','Read Holding Registers · reply'),('Returned value',int(f['current_wire_word'])),
            ('Address','Not carried in reply'),('Protocol valid',valid)]

# Display the selected current message and its raw bytes.
def message_card(case):
    fields=''.join(f'<div><span>{text(label)}</span><strong>{text(value)}</strong></div>'
                   for label,value in current_fields(case))
    st.markdown(f'<div class="message-grid">{fields}</div>',unsafe_allow_html=True)

# Show the earlier observable communication relevant to this example.
def timeline(steps):
    content=''.join(f'<div class="history-step"><span class="history-dot"></span><div><span>{text(label)}</span><strong>{text(value)}</strong></div></div>'
                    for label,value in steps)
    st.markdown('<div class="history">'+content+'</div>',unsafe_allow_html=True)

# Compare the saved predictions for the same example without inventing confidence values.
def model_table(case):
    rows=[]
    for method,name in [('B','Packet-only RF'),('D','Context-aware RF')]:
        result=case['predictions'][method]
        if not result.get('available',False):
            st.info('Model comparison not available yet.')
            return
        confidence=result.get('confidence')
        rows.append({'Model':name,'Prediction':NAMES.get(result['prediction'],result['prediction']),
                     'Confidence':'Not saved' if confidence is None else f'{confidence:.1%}'})
    st.dataframe(pd.DataFrame(rows),hide_index=True,width='stretch')

# Display one verified case with optional history and its saved prediction.
def show_case(case,number,reveal):
    decision=case['decision']; f=decision['features']; label=case['annotation']['label']
    tone='normal' if label=='normal' else 'injection'
    heading=NAMES[label] if reveal else f'Case {number}'
    st.markdown(f'<h3 class="case-title {tone if reveal else ""}">{text(heading)}</h3>',unsafe_allow_html=True)
    if not reveal:
        summary='Pump ON · coil '+str(int(f['current_wire_address'])) if decision['task']=='command' else 'Setpoint reply · '+str(int(f['current_wire_word']))
        st.markdown(f'<div class="hidden-history"><strong>{text(summary)}</strong><span>Earlier context hidden</span></div>',unsafe_allow_html=True)
        return
    if decision['task']=='command':
        mode=int(f['earlier_observed_mode'])
        steps=[('Earlier mode read',f'Mode {mode} · ON '+('permitted' if mode==1 else 'forbidden')),
               ('Current command',f'Pump ON · coil {int(f["current_wire_address"])}')]
    else:
        steps=[('Earlier write acknowledged',f'Setpoint = {int(f["earlier_acknowledged_setpoint"])}'),
               ('Current response',f'Reports {int(f["current_wire_word"])}')]
    timeline(steps)
    st.markdown(f'<div class="verdict {tone}"><span>Verified class</span><strong>{text(NAMES[label])}</strong></div>',unsafe_allow_html=True)
    model_table(case)

with demo_tab:
    if demo is None:
        st.error('Captured examples are unavailable. Check the local evidence files.')
        with st.expander('Details'): st.write(demo_error)
    else:
        controls,reveal_control=st.columns([3,2],vertical_alignment='bottom')
        with controls:
            choice=st.radio('Example',['Command injection','Response injection'],horizontal=True)
        with reveal_control:
            reveal=st.toggle('Show earlier context',value=False)
        task='command' if choice=='Command injection' else 'response'
        pair=demo['pairs'][task]
        st.markdown('**The current Modbus message is identical in both cases.**')
        message_card(pair[0])
        if not reveal: st.markdown('<p class="demo-question">Can the current message alone tell these apart?</p>',unsafe_allow_html=True)
        left,right=st.columns(2,gap='large')
        with left: show_case(pair[0],'A',reveal)
        with right: show_case(pair[1],'B',reveal)
        if reveal:
            if task=='response': st.write('Valid Modbus. The earlier acknowledged write exposes the inconsistent value.')
            else: st.write('The earlier mode read tells us whether ON is allowed.')
            if demo['prediction_source']=='saved_validation':
                st.caption('Same Random Forest family: current-message features vs current-message + context features. Predictions are saved validation outputs; confidence values were not saved.')
            st.caption('History comes from captured communication. “Verified class” comes from separate ground-truth evidence. Model inputs are listed in Evidence.')
        with st.expander('Show raw bytes'):
            st.code(pair[0]['observation']['adu_hex'],language=None)
            st.caption('Both complete messages match, including the transaction ID.')

    render_analyze_traffic()

with how_tab:
    st.subheader('From traffic to a decision')
    stages=['Captured Modbus traffic','Request/response reconstruction','Current message + earlier communication',
            'Feature extraction','Random Forest','Normal / Command injection / Response injection']
    st.markdown('<div class="pipeline">'+''.join(f'<div class="pipeline-step">{text(s)}</div>' for s in stages)+'</div>',unsafe_allow_html=True)
    left,right=st.columns(2,gap='large')
    with left:
        st.subheader('Current-message features')
        st.markdown('- Function code and unit ID\n- Request or response direction\n- Message length, address and value where carried\n- Read quantity and byte count\n- Request object role from the public map')
    with right:
        st.subheader('Context features')
        st.markdown('- Earlier observed mode\n- Earlier acknowledged setpoint\n- Paired request’s object role\n- Readback minus acknowledged setpoint\n- Whether trustworthy context is available')
    st.write('FC3 replies carry no address. Their earlier request identifies the register.')
    if demo is not None:
        with st.expander('What if earlier context is missing?'):
            case=demo['abstention']
            st.warning('No trustworthy recent anchor → abstain.')
            st.write('The message is eligible for inspection, but context is unavailable.')
            st.write('Decision:',NAMES.get(case['decision']['prediction'],case['decision']['prediction']))
            st.caption('An imputed value cannot replace missing communication history. This example is available in Evidence.')

# Present saved per-class metrics and confusion counts for the selected condition.
def metric_table(report,methods):
    rows=comparison_rows(report,methods)
    for row in rows:
        row['Macro F1']='—' if row['Macro F1'] is None else f'{row["Macro F1"]:.4f}'
        for key in ('Command recall','Response recall','False-alarm rate','Normal precision'):
            row[key]='—' if row[key] is None else f'{100*row[key]:.2f}%'
    st.dataframe(pd.DataFrame(rows),hide_index=True,width='stretch')

with results_tab:
    st.subheader('Model comparison')
    condition=st.selectbox('Test condition',list(CONDITIONS),key='test_condition')
    role=CONDITIONS[condition]; report=saved['conditions'][role]
    runs=saved['audit']['role_counts'][role]
    columns=st.columns(4)
    for column,label,value in zip(columns,['Evaluated runs','Supported decisions','Context abstentions','Captured messages'],
                                  [runs,report['common_supported'],report['context_abstentions'],report['all_adus']]):
        column.metric(label,f'{value:,}')
    metric_table(report,('B','D'))
    normal_count=sum(report['methods']['B']['common_cohort']['confusion'][0])
    st.caption(f'Saved final results. Both models use the same supported decisions. False-alarm rate uses {normal_count:,} supported normal messages. Abstentions and other traffic are not counted as correct normal predictions.')
    with st.expander('Per-class metrics and confusion matrix'):
        method_names={'Context-aware RF':'D','Packet-only RF':'B','Causal policy rules':'C',
                      'Protocol checks':'A','Packet-only RF + wire headers':'B-wire',
                      'Context-aware RF + wire headers':'D-wire'}
        chosen_model=st.selectbox('Model',list(method_names),key='metric_model')
        detail=report['methods'][method_names[chosen_model]]['common_cohort']
        metrics=[]
        for label,item in detail['per_class'].items():
            metrics.append({'Class':NAMES[label],
                'Precision':'—' if item['precision'] is None else f'{item["precision"]:.4f}',
                'Recall':'—' if item['recall'] is None else f'{item["recall"]:.4f}',
                'F1':'—' if item['f1'] is None else f'{item["f1"]:.4f}',
                'Support':item['support']})
        st.dataframe(pd.DataFrame(metrics),hide_index=True,width='stretch')
        labels=[NAMES[label] for label in detail['labels']]
        st.dataframe(pd.DataFrame(detail['confusion'],index=labels,columns=labels),width='stretch')
        st.caption('Confusion matrix: rows are true classes; columns are predictions. “—” means undefined, not zero.')
    metrics_csv=HERE/'reports/model_metrics_saved_20261026.csv'
    if metrics_csv.is_file():
        st.download_button('Download saved evaluation metrics (CSV)',metrics_csv.read_bytes(),
                           file_name=metrics_csv.name,mime='text/csv',key='download_saved_metrics')
    st.subheader('Rule-baseline results')
    metric_table(report,('C',))
    st.write('The causal rules classify every supported case correctly. The context-aware RF misses one response in the ordering test. ML has not outperformed these rules.')
    with st.expander('Protocol and wire-header comparisons'):
        st.write('The wire-header variants also receive the current transaction ID, IP addresses and ports.')
        metric_table(report,('A','B-wire','D-wire'))
    with st.expander('Evaluation coverage'):
        st.dataframe(pd.DataFrame([{'Condition':name,'Runs':saved['audit']['role_counts'][r],
                                   'Supported decisions':saved['conditions'][r]['common_supported'],
                                   'Context abstentions':saved['conditions'][r]['context_abstentions']}
                                  for name,r in CONDITIONS.items()]),hide_index=True,width='stretch')

with evidence_tab:
    st.subheader('Verify this example')
    if demo is None:
        st.info('Load the local collection to inspect packet evidence.')
    else:
        current=[c for pair in demo['pairs'].values() for c in pair]
        cases=current+demo['reference_cases']+[demo['abstention']]
        # Give an evidence example a readable selector label.
        def case_name(i):
            case=cases[i]
            kind='Saved comparison' if i<len(current) else 'Original example' if i<len(cases)-1 else 'Missing context'
            return f'{kind} · {NAMES.get(case["annotation"]["label"])} · {case["event_id"]}'
        selected=st.selectbox('Example',range(len(cases)),format_func=case_name,key='evidence_example')
        case=cases[selected]; ann=case['annotation']
        st.markdown('### Example')
        st.write('Run ID'); st.code(case['run_id'],language=None)
        st.write('Event ID'); st.code(case['event_id'],language=None)
        st.write('Application ledger line:',case['ledger_line'])
        with st.expander('Show earlier messages'):
            for name,row in case['earlier'].items():
                st.write(name.replace('_event_id','').replace('_',' ').capitalize())
                st.code(row['event_id']+'\n'+row['adu_hex'],language=None)
        st.markdown('### Captured packet')
        st.write('PCAP source'); st.code(case['source_relative']+'/capture.pcap',language=None)
        st.write('Capture SHA256'); st.code(ann['capture_sha256'],language=None)
        with st.expander('Show raw packet evidence'):
            st.code(case['observation']['adu_hex'],language=None)
            st.dataframe(pd.DataFrame(ann['frame_byte_references']),hide_index=True,width='stretch')
            st.caption('Frame numbers and byte offsets identify this exact occurrence in the capture.')
        st.markdown('### Ground truth')
        st.write('Verified class:',NAMES[ann['label']])
        with st.expander('Show ground-truth evidence'):
            st.caption('Annotation fields establish labels. They are not model inputs.')
            st.json(ann)
        with st.expander('Show model inputs'):
            features=case['decision']['features']
            st.dataframe(pd.DataFrame([{'Feature':name,'Value':str(features[name]),
                                       'Group':'Current message' if name in CURRENT else 'Context'}
                                      for name in CURRENT+CONTEXT]),hide_index=True,width='stretch')
            st.caption('These are the packet-only and context-aware RF inputs. Ground truth is kept separately.')
        st.markdown('### File integrity')
        with st.expander('Verification checks'):
            st.json(demo['checked_run_seals'])
            st.write('Collection ID'); st.code(demo['collection_id'],language=None)
            st.write('Experiment lock SHA256'); st.code(demo['lock_sha256'],language=None)
            if case['predictions']['B'].get('source'):
                st.write('Saved model predictions'); st.code(case['predictions']['B']['source'],language=None)
        if st.button('Recheck evidence and reload'):
            demonstration.clear(); saved_results.clear(); st.rerun()

with scope_tab:
    audit=saved['audit']; counts=audit['label_counts']
    st.subheader('Dataset')
    st.write('Results shown here are from a controlled software Modbus/TCP testbed.')
    cards=[('Accepted runs',audit['accepted_runs']),('Messages',sum(counts.values())),('Normal',counts['normal']),
           ('Command injection',counts['command_injection']),('Response injection',counts['response_injection']),
           ('Testbed environments',saved['environment_count']),('Excluded attempts',len(audit['excluded_attempts']))]
    for start in (0,4):
        for col,(label,value) in zip(st.columns(4 if start==0 else 3),cards[start:start+4]):
            col.metric(label,f'{value:,}')
    st.write('Train, validation and test data must be separated by complete runs, not random messages.')
    st.subheader('Scope')
    st.markdown('- Research testbed; not an industrial deployment\n- One environment and two controlled injection mechanisms\n- Results apply to the collected experimental conditions\n- Known public map, one writer and genuine earlier mode/ACK observations')
    st.write('The readback-minus-acknowledged-value feature already expresses much of the response-consistency rule.')
    st.subheader('Ground truth')
    st.write('Labels come from the experiment’s intervention and state ledgers, linked to captured packet bytes.')
    st.caption('Example comparisons use saved validation predictions. Confidence values were not recorded. Final results are read from the saved experiment reports.')

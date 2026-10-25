# Show the PCAP and CSV inference controls, predictions, and optional upload metrics.
"""Offline traffic analysis controls. All learned transforms stay frozen."""
import hashlib
import pandas as pd
import streamlit as st
from capture_replay import ATTACKS,development_captures,replay_capture
from csv_inference import (REQUIRED,OPTIONAL,LABEL_COLUMNS,SCHEMA,parse_csv,analyze_csv,
                           template_csv,observations_csv,prediction_csv,evaluate_predictions)

NAMES={'normal':'Normal','command_injection':'Command injection','response_injection':'Response injection',
       'abstain':'Insufficient context','out_of_scope':'Out of scope',None:'Rejected stream'}

# Display the source membership and whether its content was actually matched.
def show_partition(statuses):
    for status in statuses:
        st.markdown('**'+status['badge']+'**')
        st.write(status['note'])
        st.caption(status['run_id']+' · '+status['match'].replace('_',' '))

# Show predictions, exclusions, earlier anchors, exports, and optional label-based scoring.
def show_csv_result(result):
    st.subheader('Detection results')
    show_partition(result['partition_status'])
    for column,label,value in zip(st.columns(4),['Messages processed','Predictions produced','Insufficient context','Rejected rows'],
            [result['messages'],result['predictions_produced'],result['abstentions'],result['rejected_rows']]):
        column.metric(label,f'{value:,}')
    counts=result['prediction_counts']
    for column,key in zip(st.columns(3),('normal','command_injection','response_injection')):
        column.metric(NAMES[key],f'{counts.get(key,0):,}')
    st.caption(f"{result['out_of_scope']:,} messages are outside the supported classification tasks. Confidence is an uncalibrated saved-RF probability.")
    if result['rows_reordered']: st.info(f"{result['rows_reordered']:,} rows reordered by timestamp before analysis.")
    if result['rejected_streams']:
        st.warning('Some streams were rejected; no predictions were fabricated for them.')
        st.dataframe(pd.DataFrame(result['rejected_streams']),hide_index=True,width='stretch')
    category=st.selectbox('Filter predictions',['All','Normal','Command injection','Response injection','Insufficient context','Rejected stream','Out of scope'],key='csv_filter')
    rows=[r for r in result['records'] if category=='All' or NAMES[r['prediction']]==category]
    table=[]
    for row in rows:
        table.append({'Source row':row['source_row'],'Event':row['event_id'],
            'Time (UTC)':pd.Timestamp(row['observed_at_ns'],unit='ns',tz='UTC').isoformat(),
            'Function':row['function'],'Wire address':row['wire_address'],
            'Prediction':NAMES[row['prediction']],
            'Confidence':'—' if row['confidence'] is None else f"{row['confidence']:.1%}"})
    st.dataframe(pd.DataFrame(table),hide_index=True,width='stretch')
    if rows:
        selected=st.selectbox('Inspect prediction',list(range(len(rows))),
                             format_func=lambda i:f"Row {rows[i]['source_row']} · {rows[i]['event_id']}",key='csv_inspect')
        row=rows[selected]
        st.markdown('#### Current message')
        functions={1:'Read Coils',3:'Read Holding Registers',5:'Write Single Coil',6:'Write Single Register'}
        st.write(functions.get(row['function'],'Unsupported function'),f"(FC{row['function']})",'·',row['direction'])
        if row.get('unit') is not None: st.write('Unit:',row['unit'],'· Transaction ID:',row['tid'])
        st.write('Wire address:',row['wire_address'] if row['wire_address'] is not None else 'Not carried')
        if row.get('wire_word') is not None:
            word=row['wire_word']
            st.write('Wire value:',('ON (0xFF00)' if word==0xff00 else 'OFF (0x0000)') if row['function']==5 else word)
        if row.get('quantity') is not None: st.write('Quantity:',row['quantity'])
        st.code(row['adu_hex'],language=None)
        st.markdown('#### Earlier context')
        lookup={(r['run_id'],r['connection_id'],r['event_id']):r for r in result['records']}
        prior=[]
        for key,event in row['context_evidence'].items():
            if key.endswith('_event_id') and event:
                anchor=lookup[(row['run_id'],row['connection_id'],event)]
                prior.append({'Used as':key.replace('_event_id','').replace('_',' '),'Event':event,
                              'Time (ns)':anchor['observed_at_ns'],'ADU':anchor['adu_hex']})
        if prior: st.dataframe(pd.DataFrame(prior),hide_index=True,width='stretch')
        else: st.write('No usable earlier anchor for this decision.')
        st.markdown('#### Prediction')
        st.write(NAMES[row['prediction']])
        if row['confidence'] is not None: st.write(f"Confidence: {row['confidence']:.1%} (uncalibrated)")
        if row.get('reason'): st.write(row['reason'])
        if row['ground_truth']:
            st.markdown('#### Evidence')
            st.write('Uploaded ground truth:',row['ground_truth'])
            st.write('Match:',('Correct' if row['correct'] else 'Incorrect') if row['correct'] is not None else 'Not scored')
    st.download_button('Download prediction report',prediction_csv(result),file_name='c3_prediction_report.csv',mime='text/csv',key='csv_report')
    if result['ground_truth_column']:
        with st.expander('Evaluate predictions'):
            # Mandatory source status is repeated directly above upload metrics.
            show_partition(result['partition_status'])
            if st.button('Calculate uploaded-label metrics',key='csv_evaluate'):
                try:
                    report=evaluate_predictions(result)
                    st.session_state['csv_evaluation']=(result['source_sha256'],report)
                except ValueError as exc: st.error(str(exc))
            evaluated=st.session_state.get('csv_evaluation')
            if evaluated and evaluated[0]==result['source_sha256']:
                report=evaluated[1]
                st.info('Ground-truth labels were used only to score predictions, not to generate them.')
                st.caption('Uploaded labels are user-supplied. These metrics do not replace the official saved experiment results.')
                if not report['support']: st.write('No labelled predictions available to score.')
                else:
                    cols=st.columns(3)
                    cols[0].metric('Macro F1 (fixed three classes)',f"{report['macro_f1']:.4f}")
                    cols[1].metric('Scored labelled decisions',report['support'])
                    fpr=report['false_positive_rate']
                    cols[2].metric('False-positive rate','—' if fpr is None else f'{fpr:.2%}')
                    if report['missing_classes']: st.warning('Unsupported classes: '+', '.join(report['missing_classes'])+'. Their recall is undefined.')
                    details=[]
                    for name,values in report['per_class'].items():
                        details.append({'Class':name,**{k:('—' if v is None else v) for k,v in values.items()}})
                    st.dataframe(pd.DataFrame(details),hide_index=True,width='stretch')
                    st.dataframe(pd.DataFrame(report['confusion'],index=report['labels'],columns=report['labels']),width='stretch')
                    st.caption(f"Rows: true class. Columns: prediction. Normal denominator: {report['normal_denominator']}. Labelled abstentions: {report['labelled_abstentions']}; out of scope: {report['labelled_out_of_scope']}; rejected: {report['labelled_rejected']}.")

# Validate an uploaded observation file and run inference only after the user requests it.
def render_csv():
    st.subheader('Analyze CSV traffic')
    st.write('Uses the saved preprocessing and model. Nothing is retrained.')
    st.download_button('Download CSV template',template_csv(),file_name='c3_observations_template.csv',mime='text/csv',key='csv_template')
    with st.expander('What CSV should I upload?'):
        st.write('Use complete, ordered Modbus observations. Generic flow CSVs, shuffled rows with ambiguous order, model-feature tables and prediction reports are not supported.')
        st.markdown('**Required columns**'); st.code(', '.join(REQUIRED),language=None)
        st.markdown('**Optional columns**'); st.code(', '.join(OPTIONAL),language=None)
        st.write('Endpoint fields must be supplied together. Optional decoded fields must agree with raw bytes.')
        st.markdown('**Ground-truth columns**'); st.write('At most one: '+', '.join(LABEL_COLUMNS)+'. Labels are separated from predictors.')
        st.write('Time: observed_at_ns is an exact nonnegative integer, Unix nanoseconds. Stream offsets are byte positions starting at 0 separately for each direction.')
        st.write('IDs are strings. Each run + connection generation has separate history. Event IDs must be unique within a run. map_id is M0, M1 or M2 from the public testbed map.')
        st.write('adu_hex contains one complete Modbus/TCP ADU, including MBAP. Unit, transaction ID, function, address and value are decoded from these bytes.')
        st.caption('Schema '+SCHEMA+'. UTF-8; up to 20 MiB / 100,000 observations. The four template rows are synthetic format examples, not evaluation data.')
        st.write('Advanced model-feature CSVs are not accepted: feature names alone cannot verify causal history or task eligibility.')
    upload=st.file_uploader('Select CSV observations',type=['csv'],key='csv_upload')
    if upload is None: return
    data=upload.getvalue(); digest=hashlib.sha256(data).hexdigest()
    try:
        parsed=parse_csv(data)
        st.success('CSV schema valid.')
        st.write(f"{len({r['run_id'] for r in parsed['rows']}):,} runs found. {len(parsed['rows']):,} messages supplied.")
    except (ValueError,OSError) as exc:
        st.error(str(exc)); return
    trust=st.checkbox('These observations use the declared single-writer and trusted-anchor testbed policy.',key='csv_trust')
    if st.button('Run detection on CSV',disabled=not trust,key='csv_run',type='primary'):
        with st.spinner('Validating streams and running detection…'):
            try:
                result=analyze_csv(data,trusted_single_writer=True)
                st.session_state['csv_result']=result
                st.session_state.pop('csv_evaluation',None)
            except (ValueError,OSError,KeyError) as exc:
                st.session_state.pop('csv_result',None); st.error(str(exc))
    result=st.session_state.get('csv_result')
    if result and result['source_sha256']==digest: show_csv_result(result)

# Keep the captured-byte replay route available alongside CSV inference.
def render_pcap():
    st.write('Reconstruct captured TCP bytes and run the saved RF now.')
    try:
        captures=development_captures(); choices=list(captures)
        selected=st.selectbox('Recording',choices,index=choices.index('MX025'),key='capture_recording',
                             format_func=lambda run:run+' · '+captures[run]['intended_evaluation_role'])
        role=captures[selected]['intended_evaluation_role']
        st.caption('TRAINING RUN · Implementation replay only' if role=='train' else 'VALIDATION RUN · Development data')
        if st.button('Run detection',key='run_capture_detection',type='primary'):
            with st.spinner('Reading captured bytes and running detection…'):
                st.session_state['capture_detection']=replay_capture(selected)
        replay=st.session_state.get('capture_detection')
        if replay is None or replay['planned_id']!=selected: return
        st.success('Detection complete · fresh inference on an existing development capture')
        for col,label,value in zip(st.columns(4),['Messages replayed','Injection alerts','Abstentions','Out of scope'],
                                  [replay['messages'],replay['alerts'],replay['abstentions'],replay['out_of_scope']]):
            col.metric(label,f'{value:,}')
        include=st.checkbox('Show normal and abstained decisions',key='show_replay_normal')
        rows=[r for r in replay['records'] if r['context_aware'] in ATTACKS or (include and r['eligible'])]
        table=pd.DataFrame([{'Message':r['message_number'],'Function':r['function'],
            'Packet-only RF':NAMES[r['packet_only']],'Context-aware RF':NAMES[r['context_aware']],
            'Confidence':'—' if r['confidence'] is None else f"{r['confidence']:.1%}",
            'PCAP frame':r['wire_complete_frame']} for r in rows])
        if table.empty: st.info('No injection alerts. Enable normal and abstained decisions to inspect the recording.')
        else: st.dataframe(table,hide_index=True,width='stretch')
        st.caption('Confidence is computed now by the saved RF and is uncalibrated. No labels or simulator state are used for detection. This replay does not change the saved evaluation metrics.')
        with st.expander('Replay source and packet details'):
            st.code(replay['pcap'],language=None); st.code(replay['capture_sha256'],language=None)
            for row in rows[:1]:
                st.code(row['adu_hex'],language=None)
                st.json({'context_evidence':row['context_evidence'],'frame_byte_references':row['frame_byte_references']})
        export=pd.DataFrame([{k:v for k,v in r.items() if k not in ('context_evidence','frame_byte_references')} for r in replay['records']])
        st.download_button('Download replay decisions (CSV)',export.to_csv(index=False).encode('utf-8'),file_name=selected+'_pcap_inference.csv',mime='text/csv',key='download_replay')
        st.download_button('Download observations (CSV input)',observations_csv(replay['observations']),file_name=selected+'_observations.csv',mime='text/csv',key='download_observations')
    except (ValueError,OSError,KeyError) as exc: st.error(f'Capture replay unavailable: {exc}')

# Let the user choose PCAP or CSV while explaining where their inference routes join.
def render_analyze_traffic():
    st.divider(); st.subheader('Analyze traffic')
    source=st.radio('Input source',['Recorded PCAP','CSV'],horizontal=True,key='traffic_source')
    st.caption('PCAP: packets → observations. CSV: extracted observations. Both use the same causal context, saved preprocessing and saved RF.')
    with st.expander('Input architecture'):
        st.code('PCAP → TCP/Modbus parser ─┐\n                          ├→ observations → causal context\nCSV observations ─────────┘\n        → saved preprocessing → saved RF → predictions',language=None)
    if source=='Recorded PCAP': render_pcap()
    else: render_csv()

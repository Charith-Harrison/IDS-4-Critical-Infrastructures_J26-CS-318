# Give PCAP and CSV observations the same context-building and saved-model path.
"""Shared PCAP/CSV observation -> causal state -> frozen RF inference route."""
from runtime import Detector,load_locked_models,predict_batch

PUBLIC_FIELDS=('event_id','connection_id','direction','stream_offset','adu_hex','observed_at_ns',
               'source_ip','destination_ip','source_port','destination_port')

# Filter to public observation fields, replay all messages, then call the saved RF pipelines.
def infer_observations(observations,mapping,models=None):
    detector=Detector(mapping,trusted_single_writer=True)
    decoded=[]
    for row in observations:
        # IDs identify occurrences/state. No source/run/label fields become X.
        result=detector.observe({key:row[key] for key in PUBLIC_FIELDS if key in row})
        if result['processing_status'] not in ('complete','insufficient_context','out_of_scope'):
            raise ValueError(result.get('reason','Observation exceeds the qualified detector contract'))
        decoded.append(result)
    # Only load and predict here; there is no fit or threshold selection during upload.
    models=load_locked_models() if models is None else models
    return decoded,{name:predict_batch(decoded,models,name) for name in ('B','D')}

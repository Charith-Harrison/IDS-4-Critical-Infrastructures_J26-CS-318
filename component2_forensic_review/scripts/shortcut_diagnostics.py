"""Forensic diagnostics against inherited labels; no final model or preprocessing exports.

Diagnostic estimator fitting is expressly requested by the audit. This script never
loads any saved model or runs the research training pipeline.
"""
from pathlib import Path
import json, sys, importlib.util
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
E=ROOT/'evidence'

def metrics(y,p):
    y=np.asarray(y,dtype=bool); p=np.asarray(p,dtype=bool)
    tp=int((y&p).sum()); fp=int((~y&p).sum()); tn=int((~y&~p).sum()); fn=int((y&~p).sum())
    return dict(TP=tp,FP=fp,TN=tn,FN=fn,precision=tp/(tp+fp) if tp+fp else 0.,
        recall=tp/(tp+fn) if tp+fn else 0.,F1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.,
        FPR=fp/(fp+tn) if fp+tn else None)

def rules(d):
    fc=d.func_code.to_numpy(); ml=d.modbus_len.to_numpy(); sz=d.packet_size.to_numpy()
    reg=d.register_start.to_numpy(); q=d.quantity.to_numpy()
    src=d.src_ip.to_numpy(); dst=d.dst_ip.to_numpy()
    return {'modbus_len_eq_3':ml==3,'packet_size_eq_75':sz==75,'func_code_eq_5':fc==5,
        'fc5_and_len3':(fc==5)&(ml==3),'register_eq_0':reg==0,'register_ge_100':reg>=100,
        'quantity_eq_0':q==0,'quantity_gt_1':q>1,
        'read_and_quantity_gt_1':np.isin(fc,[1,2,3,4])&(q>1),
        'direction_IED_to_HMI':np.isin(src,['185.175.0.4','185.175.0.5','185.175.0.8'])&np.isin(dst,['185.175.0.2','185.175.0.3']),
        'direction_HMI_to_IED':np.isin(dst,['185.175.0.4','185.175.0.5','185.175.0.8'])&np.isin(src,['185.175.0.2','185.175.0.3']),
        'direction_external_attacker':src=='185.175.0.7'}

def add_rules(out,d,corpus,I=None,window_y=None):
    for name,p in rules(d).items():
        out.append(dict(corpus=corpus,level='packet',method='fixed_rule',rule_or_model=name,grouping='population_descriptive',**metrics(d.label,p)))
        if I is not None:
            out.append(dict(corpus=corpus,level='window',method='fixed_rule_any_constituent',rule_or_model=name,grouping='population_descriptive',**metrics(window_y,p[I].any(1))))

def distributions(d,corpus):
    frames=[]
    for col in ['func_code','modbus_len','packet_size','register_start','quantity']:
        t=d.groupby(['label',col],dropna=False).size().rename('count').reset_index()
        t['feature']=col; t=t.rename(columns={col:'value'}); t['corpus']=corpus
        frames.append(t[['corpus','feature','label','value','count']])
    t=d.groupby(['label','func_code','modbus_len','packet_size','register_start','quantity','src_ip','dst_ip'],dropna=False).size().rename('count').reset_index()
    t.to_csv(E/f'{corpus}_joint_packet_shapes.csv',index=False)
    pd.concat(frames).to_csv(E/f'{corpus}_class_distributions.csv',index=False)

def load_sklearn():
    # The primary runtime has no sklearn. Reuse the existing task-local C3 installation
    # only for this missing analysis capability, or newly isolated forensic dependencies.
    for dep in [ROOT/'.deps',Path(r'D:\VSCode\GitHub\4th Year Cyber\output\c3_ml_deps')]:
        if (dep/'sklearn').exists(): sys.path.insert(0,str(dep)); break
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    import sklearn
    return DecisionTreeClassifier,LogisticRegression,StandardScaler,make_pipeline,sklearn.__version__

def main():
    out=[]
    raw=pd.read_csv(E/'recon_labeled_packets_ALL.csv')
    legacy_idx=np.load(E/'legacy_window_index_recovered.npy')
    # Only labels from recovered constituent membership, checked by sequence audit.
    legacy_y=raw.label.to_numpy()[legacy_idx].max(1)
    add_rules(out,raw,'legacy',legacy_idx,legacy_y); distributions(raw,'legacy')
    p=E/'diagnostic_reconstruction'
    d=pd.read_csv(p/'packets_rebuilt.csv'); w=pd.read_csv(p/'windows.csv'); I=np.load(p/'window_index.npy')
    add_rules(out,d,'diagnostic_reconstruction',I,w.label.to_numpy()); distributions(d,'diagnostic_reconstruction')
    # Conservative dependencies: combine ALL chunks/days/views from each attack-source
    # family rather than pretending the 10 inherited capture IDs are independent runs.
    group=np.where(d.capture_group.str.startswith('G03'),'external_source_family',
        np.where(d.capture_group.str.match(r'G0[4-8]'),'compromised_scada_source_family','benign_or_other_source_family'))
    wg=group[I[:,0]]
    assert (group[I]==wg[:,None]).all()
    fold_info=[]
    model_status={}
    try:
        DT,LR,SC,pipe,ver=load_sklearn()
        model_status={'status':'completed','sklearn_version':ver,
            'scope':'Descriptive inherited-label diagnostic. Source-family holdouts prevent known file/view/window overlap; do not prove independent campaigns or valid targets.',
            'estimators':'DecisionTree(max_depth=3,random_state=42); StandardScaler(train only)+LogisticRegression(C=1,max_iter=250,random_state=42); no tuning, balancing, SMOTE or exported estimators.'}
        base=d[['func_code','modbus_len','register_start','quantity','packet_size']].to_numpy(float)
        base[:,3]=np.log1p(base[:,3])
        # Fixed protocol code indicators avoid imposing numeric order on function codes.
        X=np.column_stack([(base[:,0,None]==np.arange(1,7)).astype(float),base[:,1:]])
        for features,xx in [('all_static',X),('without_size_length',X[:,[0,1,2,3,4,5,7,8]])]:
            # columns fc1..fc6, len,reg,logq,size
            for level,xx2,yy,gg in [('packet',xx,d.label.to_numpy(),group),
                ('window',np.column_stack([xx[I].mean(1),xx[I].min(1),xx[I].max(1),xx[I].std(1)]),w.label.to_numpy(),wg)]:
                for name in ['decision_tree_depth3','logistic_regression_default_C1']:
                    pred=np.zeros(len(yy),dtype=int)
                    for hold in sorted(np.unique(gg)):
                        te=gg==hold; tr=~te
                        if len(np.unique(yy[tr]))<2:
                            pred[te]=int(np.unique(yy[tr])[0]); status='single_class_train_constant_prediction'
                        else:
                            model=DT(max_depth=3,random_state=42) if name.startswith('decision') else pipe(SC(),LR(C=1.,max_iter=250,random_state=42))
                            model.fit(xx2[tr],yy[tr]); pred[te]=model.predict(xx2[te]); status='fit_train_only'
                        fold_info.append(dict(level=level,features=features,model=name,held_out=hold,train_rows=int(tr.sum()),test_rows=int(te.sum()),
                            train_positives=int(yy[tr].sum()),test_positives=int(yy[te].sum()),status=status,**metrics(yy[te],pred[te])))
                    out.append(dict(corpus='diagnostic_reconstruction',level=level,method='untuned_static_diagnostic',rule_or_model=name+'__'+features,
                        grouping='leave_one_conservative_source_family_out_3_folds',**metrics(yy,pred)))
        pd.DataFrame(fold_info).to_csv(E/'static_baseline_fold_metrics.csv',index=False)
    except Exception as ex:
        model_status={'status':'unavailable','reason':repr(ex)}
        raise
    finally:
        pd.DataFrame(out).to_csv(ROOT/'shortcut_analysis.csv',index=False)
        (E/'static_baseline_protocol.json').write_text(json.dumps(model_status,indent=2))
    checks={}
    for name,dd,idx,yw in [('legacy',raw,legacy_idx,legacy_y),('diagnostic_reconstruction',d,I,w.label.to_numpy())]:
        checks[name]={'packets':len(dd),'positives':int(dd.label.sum()),'windows':len(idx),'positive_windows':int(yw.sum()),
            'len3_positive_packets':int(((dd.label==1)&(dd.modbus_len==3)).sum()),
            'len3_normal_packets':int(((dd.label==0)&(dd.modbus_len==3)).sum()),
            'len3_positive_windows':int(((yw==1)&(dd.modbus_len.to_numpy()[idx]==3).any(1)).sum()),
            'len3_normal_windows':int(((yw==0)&(dd.modbus_len.to_numpy()[idx]==3).any(1)).sum())}
    (E/'shortcut_summary.json').write_text(json.dumps(checks,indent=2))
    print(json.dumps(checks,indent=2),flush=True)

if __name__=='__main__': main()

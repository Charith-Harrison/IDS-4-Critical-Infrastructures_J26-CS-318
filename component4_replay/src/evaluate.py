"""Shared binary metric definitions for every comparison."""
import numpy as np
from sklearn.metrics import (confusion_matrix, roc_auc_score, average_precision_score,
                             precision_recall_fscore_support, balanced_accuracy_score)


def evaluate(y, prediction, probability=None):
    y=np.asarray(y); prediction=np.asarray(prediction)
    if not len(y) or not set(np.unique(y)).issubset({0,1}): raise ValueError('Nonempty binary truth required')
    if len(prediction)!=len(y) or not set(np.unique(prediction)).issubset({0,1}): raise ValueError('Invalid binary predictions')
    tn,fp,fn,tp=confusion_matrix(y,prediction,labels=[0,1]).ravel()
    p,r,f,_=precision_recall_fscore_support(y,prediction,average='binary',zero_division=0)
    m=dict(TP=int(tp),FP=int(fp),TN=int(tn),FN=int(fn),support=len(y),
           precision=float(p),recall=float(r),F1=float(f),accuracy=float(np.mean(y==prediction)),
           false_positive_rate=float(fp/(fp+tn)) if fp+tn else None,
           balanced_accuracy=float(balanced_accuracy_score(y,prediction)),ROC_AUC=None,PR_AUC_average_precision=None)
    if probability is not None:
        probability=np.asarray(probability)
        if len(probability)!=len(y) or not np.isfinite(probability).all() or ((probability<0)|(probability>1)).any(): raise ValueError('Invalid probabilities')
        if len(np.unique(y))==2:
            m.update(ROC_AUC=float(roc_auc_score(y,probability)),
                     PR_AUC_average_precision=float(average_precision_score(y,probability)))
    return m

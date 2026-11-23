#!/usr/bin/env python3
"""
make_eval_figures.py -- results figures from the REAL per-path scores.
Reads scores_all.csv (label, n_steps, n_ioc, R, S_seq, S_temp, S_ctx,
baseline_evidence, stages) and writes:
  fig_pr_roc.(pdf|png)             PR curves (main) and ROC curves
  fig_component_separation.(pdf|png)  per-component benign vs attack
All values are computed, nothing assigned.
Usage: python make_eval_figures.py scores_all.csv
"""
import sys, csv, collections
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

def roc_curve(scores, labels):
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    P = sum(labels); N = len(labels) - P
    tp = fp = 0; xs=[0.0]; ys=[0.0]; prev=None
    for s, y in pairs:
        if s != prev: xs.append(fp/N); ys.append(tp/P); prev=s
        if y==1: tp+=1
        else: fp+=1
    xs.append(fp/N); ys.append(tp/P)
    auc=0.0
    for i in range(1,len(xs)): auc+=(xs[i]-xs[i-1])*(ys[i]+ys[i-1])/2
    return xs, ys, auc

def pr_curve(scores, labels):
    # average precision at distinct thresholds, ties grouped (matches pipeline)
    P=sum(labels)
    posc=collections.Counter(s for s,y in zip(scores,labels) if y==1)
    negc=collections.Counter(s for s,y in zip(scores,labels) if y==0)
    thr=sorted(set(scores),reverse=True)
    tp=fp=0; rec=[0.0]; prec=[1.0]; ap=0.0; prev=0.0
    for t in thr:
        tp+=posc.get(t,0); fp+=negc.get(t,0)
        r=tp/P; p=tp/(tp+fp)
        rec.append(r); prec.append(p); ap+=(r-prev)*p; prev=r
    return rec, prec, ap

def main(path):
    rows=[r for r in csv.DictReader(open(path)) if r["label"] in ("attack","benign")]
    y=[1 if r["label"]=="attack" else 0 for r in rows]
    col=lambda k:[float(r[k]) for r in rows]
    configs=[
        ("Path length",        col("n_steps"),          "#9aa7b4","dotted"),
        ("Technique count",    col("baseline_evidence"),"#6b7a8c","dashed"),
        ("Sequence $S_{seq}$", col("S_seq"),             "#4c78a8","solid"),
        ("Full $R(p)$",        col("R"),                 "#1b3a5c","solid"),
    ]
    fig,(axp,axr)=plt.subplots(1,2,figsize=(9.2,4.0))
    for name,s,c,ls in configs:
        rec,prec,ap=pr_curve(s,y)
        axp.step(rec,prec,where="post",color=c,ls=ls,lw=2,label="%s (AP %.3f)"%(name,ap))
    axp.set_xlabel("Recall"); axp.set_ylabel("Precision")
    axp.set_xlim(0,1.02); axp.set_ylim(0,1.02)
    axp.set_title("Precision-recall (4 attack vs. %d benign)"%y.count(0),fontsize=9.5)
    axp.legend(fontsize=7.5,frameon=False,loc="upper right"); axp.grid(alpha=0.25)
    for name,s,c,ls in configs:
        xs,ys,auc=roc_curve(s,y)
        axr.plot(xs,ys,color=c,ls=ls,lw=2,label="%s (AUC %.3f)"%(name,auc))
    axr.plot([0,1],[0,1],":",color="#cccccc",lw=1)
    axr.set_xlabel("False positive rate"); axr.set_ylabel("True positive rate")
    axr.set_xlim(0,1); axr.set_ylim(0,1.02)
    axr.set_title("ROC",fontsize=9.5)
    axr.legend(fontsize=7.5,frameon=False,loc="lower right"); axr.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig("fig_pr_roc.pdf"); fig.savefig("fig_pr_roc.png",dpi=200)
    print("wrote fig_pr_roc.pdf / .png")

    # component separation
    rng=np.random.default_rng(0)
    atk=[r for r in rows if r["label"]=="attack"]; ben=[r for r in rows if r["label"]=="benign"]
    comps=[("$S_{seq}$","S_seq"),("$S_{temp}$","S_temp"),("$S_{ctx}$","S_ctx")]
    idx=rng.choice(len(ben),size=min(2500,len(ben)),replace=False)
    bsub=[ben[j] for j in idx]
    fig,ax=plt.subplots(figsize=(5.4,3.9))
    for i,(_,k) in enumerate(comps,start=1):
        yb=[float(r[k]) for r in bsub]; xb=i+(rng.random(len(yb))-0.5)*0.5
        ax.scatter(xb,yb,color="#5b6b7d",s=6,alpha=0.30,zorder=1,
                   label="benign paths (random 2,500-path sample)" if i==1 else None)
        p99=sorted(float(r[k]) for r in ben)[int(0.99*len(ben))]
        ax.plot([i-0.32,i+0.32],[p99,p99],color="#111111",lw=1.6,zorder=2,
                label="benign 99th percentile (all paths)" if i==1 else None)
        ya=[float(r[k]) for r in atk]; xa=i+(rng.random(len(ya))-0.5)*0.16
        ax.scatter(xa,ya,color="#c0392b",s=42,zorder=3,edgecolor="white",linewidth=0.6,
                   label="attack paths" if i==1 else None)
    ax.set_xticks(range(1,len(comps)+1)); ax.set_xticklabels([c for c,_ in comps])
    ax.set_xlim(0.5,len(comps)+0.5); ax.set_ylabel("Component score"); ax.set_ylim(-0.03,1.05)
    ax.set_title("Score components: benign paths vs. the 4 attack paths",fontsize=10)
    ax.legend(fontsize=7.5,frameon=False,loc="center right"); ax.grid(alpha=0.2,axis="y")
    fig.tight_layout()
    fig.savefig("fig_component_separation.pdf"); fig.savefig("fig_component_separation.png",dpi=200)
    print("wrote fig_component_separation.pdf / .png")

if __name__=="__main__":
    main(sys.argv[1] if len(sys.argv)>1 else "scores_all.csv")

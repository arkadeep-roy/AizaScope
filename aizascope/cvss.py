from __future__ import annotations

import math

AV={"N":0.85,"A":0.62,"L":0.55,"P":0.20}
AC={"L":0.77,"H":0.44}
UI={"N":0.85,"R":0.62}
CIA={"H":0.56,"L":0.22,"N":0.0}
PR_U={"N":0.85,"L":0.62,"H":0.27}
PR_C={"N":0.85,"L":0.68,"H":0.50}

def round_up_1(value: float) -> float:
    return math.ceil(value*10.0-1e-10)/10.0

def parse_vector(vector: str) -> dict[str,str]:
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError("Only CVSS:3.1 vectors are supported")
    metrics={}
    for part in vector.split("/",1)[1].split("/"):
        if part:
            k,v=part.split(":",1); metrics[k]=v
    missing={"AV","AC","PR","UI","S","C","I","A"}-set(metrics)
    if missing:
        raise ValueError("Missing CVSS metrics: "+", ".join(sorted(missing)))
    return metrics

def severity_from_score(score: float) -> str:
    if score==0: return "NONE"
    if score<4.0: return "LOW"
    if score<7.0: return "MEDIUM"
    if score<9.0: return "HIGH"
    return "CRITICAL"

def score_vector(vector: str) -> tuple[float,str]:
    m=parse_vector(vector); changed=m["S"]=="C"; pr=(PR_C if changed else PR_U)
    impact=1-((1-CIA[m["C"]])*(1-CIA[m["I"]])*(1-CIA[m["A"]]))
    exploit=8.22*AV[m["AV"]]*AC[m["AC"]]*pr[m["PR"]]*UI[m["UI"]]
    if impact<=0: return 0.0,"NONE"
    if changed:
        impact_sub=7.52*(impact-0.029)-3.25*((impact-0.02)**15)
        base=round_up_1(min(1.08*(impact_sub+exploit),10.0))
    else:
        impact_sub=6.42*impact
        base=round_up_1(min(impact_sub+exploit,10.0))
    return base,severity_from_score(base)

def score_hint(vector_hint: str) -> dict[str,object]:
    if not vector_hint.startswith("CVSS:3.1/"):
        return {"vector":vector_hint,"score":None,"severity":"MANUAL"}
    try:
        score,severity=score_vector(vector_hint); return {"vector":vector_hint,"score":score,"severity":severity}
    except Exception as exc:
        return {"vector":vector_hint,"score":None,"severity":"ERROR","error":str(exc)}

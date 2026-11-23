import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle, FancyArrowPatch

DARK="#1b4463"; GREY_FACE="#ededed"; GREY_EDGE="#b0b0b0"; GREY_TXT="#8a8a8a"
fig,ax=plt.subplots(figsize=(13,5.2))
R=0.52
nodes={
 "sp":  (0.0, 0.0, "T1566.002","Spearphish", True),
 "ue":  (2.0, 0.0, "T1204.001","User Exec", True),
 "wi":  (4.0, 0.0, "T1583.006","Web Infra", True),
 "pc":  (6.0, 1.15,"T1056.003","Portal Capture", True),
 "ic":  (6.0,-1.15,"T1056.002","Input Capture", True),
 "c2":  (8.0, 0.0, "T1071.001","Web C2", True),
 "rl":  (10.0,0.0, "T1090","Relay (ngrok)", True),
 "ig":  (4.0, 1.9, "T1105","Ingress", False),   # untraversed admissible
}
def draw_node(k):
    x,y,tid,lab,solid=nodes[k]
    if solid:
        ax.add_patch(Circle((x,y),R,facecolor=DARK,edgecolor=DARK,zorder=3))
        ax.text(x,y+0.12,tid,ha="center",va="center",color="white",fontsize=11,fontweight="bold",zorder=4)
        ax.text(x,y-0.17,lab,ha="center",va="center",color="white",fontsize=10,zorder=4)
    else:
        ax.add_patch(Circle((x,y),R,facecolor=GREY_FACE,edgecolor=GREY_EDGE,lw=1.6,ls=(0,(4,3)),zorder=3))
        ax.text(x,y+0.12,tid,ha="center",va="center",color=GREY_TXT,fontsize=11,fontweight="bold",zorder=4)
        ax.text(x,y-0.17,lab,ha="center",va="center",color=GREY_TXT,fontsize=10,zorder=4)
for k in nodes: draw_node(k)
def arrow(a,b,solid=True):
    xa,ya=nodes[a][0],nodes[a][1]; xb,yb=nodes[b][0],nodes[b][1]
    import math
    dx,dy=xb-xa,yb-ya; d=math.hypot(dx,dy); ux,uy=dx/d,dy/d
    p1=(xa+ux*R, ya+uy*R); p2=(xb-ux*R, yb-uy*R)
    if solid:
        ax.add_patch(FancyArrowPatch(p1,p2,arrowstyle="-|>",mutation_scale=18,lw=2.2,color=DARK,zorder=2))
    else:
        ax.add_patch(FancyArrowPatch(p1,p2,arrowstyle="-|>",mutation_scale=15,lw=1.6,color=GREY_EDGE,ls=(0,(4,3)),zorder=2))
for a,b in [("sp","ue"),("ue","wi"),("wi","pc"),("wi","ic"),("pc","c2"),("ic","c2"),("c2","rl")]:
    arrow(a,b,True)
arrow("wi","ig",False)
ax.set_xlim(-1,11); ax.set_ylim(-2.1,2.8); ax.axis("off")
fig.tight_layout()
fig.savefig("fig_technique_graph_v2.png",dpi=200,bbox_inches="tight")
fig.savefig("fig_technique_graph_v2.pdf",bbox_inches="tight")
print("wrote fig_technique_graph_v2.png/.pdf")

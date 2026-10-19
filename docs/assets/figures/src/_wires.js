// Draws orthogonal connectors between boxes after layout.
// window.WIRES = [[fromId, fromSide, toId, toSide, {dash, label, color, off}], ...]
function drawWires(){
  const fig=document.getElementById('fig'); const fr=fig.getBoundingClientRect();
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('class','wires'); svg.setAttribute('width',fr.width); svg.setAttribute('height',fr.height);
  svg.innerHTML='<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#6b7280"/></marker></defs>';
  const pt=(id,side,off)=>{const r=document.getElementById(id).getBoundingClientRect();
    const x0=r.left-fr.left,y0=r.top-fr.top; off=off||0;
    if(side==='top')return[x0+r.width/2+off,y0]; if(side==='bottom')return[x0+r.width/2+off,y0+r.height];
    if(side==='left')return[x0,y0+r.height/2+off]; return[x0+r.width,y0+r.height/2+off];};
  for(const w of (window.WIRES||[])){
    const [a,as,b,bs,o={}]=w; const [x1,y1]=pt(a,as,o.off1); let [x2,y2]=pt(b,bs,o.off2); if(o.straight){ if(as==='left'||as==='right') y2=y1; else x2=x1; } let d;
    const v=s=>s==='top'||s==='bottom';
    if(v(as)&&v(bs)){ if(Math.abs(x1-x2)<1) d=`M${x1},${y1} V${y2}`; else {const ym=o.mid!==undefined?o.mid:(y1+y2)/2; d=`M${x1},${y1} V${ym} H${x2} V${y2}`;} }
    else if(!v(as)&&!v(bs)){ if(Math.abs(y1-y2)<1) d=`M${x1},${y1} H${x2}`; else {const xm=o.mid!==undefined?o.mid:(x1+x2)/2; d=`M${x1},${y1} H${xm} V${y2} H${x2}`;} }
    else if(!v(as)&&v(bs)) d=`M${x1},${y1} H${x2} V${y2}`;
    else d=`M${x1},${y1} V${y2} H${x2}`;
    const p=document.createElementNS('http://www.w3.org/2000/svg','path');
    p.setAttribute('d',d); p.setAttribute('fill','none'); p.setAttribute('stroke',o.color||'#6b7280'); p.setAttribute('stroke-width','2');
    if(o.dash) p.setAttribute('stroke-dasharray','6 5'); if(!o.noarrow) p.setAttribute('marker-end','url(#ah)');
    svg.appendChild(p);
    if(o.label){const l=document.createElement('div'); l.className='lbl'; l.textContent=o.label; fig.appendChild(l);
      const lw=l.getBoundingClientRect().width, lh=l.getBoundingClientRect().height;
      let lx=(x1+x2)/2-lw/2, ly=(y1+y2)/2-lh/2; if(o.lx!==undefined){lx=o.lx} if(o.ly!==undefined){ly=o.ly}
      if(o.at==='start'){lx=x1+6; ly=y1-lh-3}
      if(o.at==='below'){lx=x1+8; ly=y1+6}
      if(o.rot){const cx=(o.mid!==undefined?o.mid:(x1+x2)/2), cy=(y1+y2)/2; lx=cx-lw/2; ly=cy-lh/2; l.style.transform='rotate(-90deg)';}
      l.style.left=lx+'px'; l.style.top=ly+'px';}
  }
  fig.insertBefore(svg,fig.firstChild);
}
window.addEventListener('load',()=>{document.fonts.ready.then(()=>{drawWires();document.body.setAttribute('data-ready','1')})});

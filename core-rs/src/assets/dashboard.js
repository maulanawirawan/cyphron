// Dashboard cyphron — tanpa build step, tanpa dependency.
// Audit 2026-10: data scan dirender via textContent + DOM terstruktur —
// nama path dari findings tidak boleh ditafsirkan sebagai markup.
fetch('/api/runs').then(r=>r.json()).then(rows=>{
  const b=document.querySelector('#t tbody');
  for(const r of rows){
    const tr=document.createElement('tr');
    const td=(txt)=>{const c=document.createElement('td'); c.textContent=String(txt??''); return c;};
    tr.appendChild(td(r.rel));
    tr.appendChild(td(r.total));
    const pillTd=document.createElement('td');
    const span=document.createElement('span'); span.className='pill';
    span.textContent=String(r.reportable??'');
    pillTd.appendChild(span);
    tr.appendChild(pillTd);
    tr.appendChild(td(r.requests));
    const linkTd=document.createElement('td');
    const pdfA=document.createElement('a');
    pdfA.href='/report?path='+encodeURIComponent(r.pdf||'');
    pdfA.textContent='PDF';
    const jsonA=document.createElement('a');
    jsonA.href='/api/run?path='+encodeURIComponent(r.rel);
    jsonA.textContent='JSON';
    linkTd.appendChild(pdfA);
    linkTd.appendChild(document.createTextNode(' · '));
    linkTd.appendChild(jsonA);
    tr.appendChild(linkTd);
    b.appendChild(tr);
  }
  if(!rows.length){
    const tr=document.createElement('tr');
    const c=document.createElement('td');
    c.colSpan=5;
    c.textContent='belum ada findings.json di direktori ini';
    tr.appendChild(c);
    b.appendChild(tr);
  }
});

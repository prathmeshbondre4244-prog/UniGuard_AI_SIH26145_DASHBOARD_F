const $=id=>document.getElementById(id);
async function api(url,options={}){const r=await fetch(url,{headers:{"Content-Type":"application/json"},...options});const data=await r.json();if(!r.ok)throw new Error(data.detail||"Request failed");return data}
let threatTimeline=[];let lastAlertTotal=null;let lastAlerts=[];let lastFlows=[];
const pageNames={dashboard:"Security Overview",traffic:"Live Traffic",flows:"Flow Analysis",detection:"AI Detection",alerts:"Threat Alerts",analytics:"Threat Analytics",model:"Model Information",system:"System Status",incidents:"Incident Center",network:"Network Map",dns:"DNS Intelligence",validation:"Validation Lab",config:"Configuration"};
function showPage(name){document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));$('page-'+name).classList.add('active');document.querySelectorAll('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.page===name));$('pageTitle').textContent=pageNames[name]||'Security Overview'}
document.querySelectorAll('.nav-item').forEach(b=>b.onclick=()=>showPage(b.dataset.page));document.querySelectorAll('[data-page-jump]').forEach(b=>b.onclick=()=>showPage(b.dataset.pageJump));
function esc(v){return String(v??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function alertHtml(x) {
    const sev = (x.severity || 'SAFE').toLowerCase();

    const color =
        sev === 'critical' ? 'red' :
        sev === 'high' ? 'orange' :
        sev === 'medium' ? 'yellow' :
        'blue';

    const icon =
        sev === 'critical' ? '🔴' :
        sev === 'high' ? '🟠' :
        sev === 'medium' ? '🟡' :
        '🔵';

    const threat = esc(x.threat_type || 'Security Alert');
    const confidence = esc(x.confidence ?? 0);
    const timestamp = esc(x.timestamp || '—');
    const source = esc(x.source || '—');
    const destination = esc(x.destination || '—');
    const protocol = esc(x.protocol || '—');

    const evidence = (x.evidence || [])
        .map(e => `<li>${esc(e)}</li>`)
        .join('');

    return `
        <div class="alert-card ${sev}">

            <div class="alert-top">

                <div class="alert-title">
                    <span class="threat-icon">${icon}</span>

                    <div>
                        <div class="alert-name">
                            ${threat}
                        </div>

                        <div class="alert-label">
                            AI DETECTION EVENT
                        </div>
                    </div>
                </div>

                <div class="alert-confidence ${color}">
                    <strong>${confidence}%</strong>
                    <span>CONFIDENCE</span>
                </div>

            </div>


            <div class="alert-details">

                <div class="detail-item">
                    <span>SEVERITY</span>
                    <strong class="${color}">
                        ${esc(x.severity || 'SAFE')}
                    </strong>
                </div>

                <div class="detail-item">
                    <span>PROTOCOL</span>
                    <strong>${protocol}</strong>
                </div>

                <div class="detail-item">
                    <span>TIME</span>
                    <strong>${timestamp}</strong>
                </div>

            </div>


            <div class="traffic-path">

                <div>
                    <span>SOURCE</span>
                    <strong>${source}</strong>
                </div>

                <div class="path-arrow">
                    →
                </div>

                <div>
                    <span>DESTINATION</span>
                    <strong>${destination}</strong>
                </div>

            </div>


            <div class="alert-evidence">

                <div class="evidence-title">
                    DETECTION EVIDENCE
                </div>

                <ul>
                    ${
                        evidence ||
                        '<li>No additional evidence available</li>'
                    }
                </ul>

            </div>

        </div>
    `;
}
function renderAlerts(alerts){lastAlerts=alerts||[];$('alertNavCount').textContent=alerts.length;$('recentAlerts').innerHTML=alerts.length?alerts.slice(0,4).map(alertHtml).join(''):'<div class="empty">No alerts yet. Run the safe demo or start passive capture.</div>';$('allAlerts').innerHTML=alerts.length?alerts.map(alertHtml).join(''):'<div class="empty">No alerts yet.</div>'}
function severityBucket(a){const s=(a?.severity||'').toLowerCase();if(s==='critical'||s==='high')return 'malicious';if(s==='medium')return 'suspicious';return 'normal'}
function seedThreatTimeline(alerts){const sorted=(alerts||[]).slice().sort((a,b)=>String(a.timestamp||'').localeCompare(String(b.timestamp||'')));let total=0;const points=sorted.slice(-18).map(a=>{total++;return{time:String(a.timestamp||''),newAlerts:1,total,normal:severityBucket(a)==='normal'?1:0,suspicious:severityBucket(a)==='suspicious'?1:0,malicious:severityBucket(a)==='malicious'?1:0}});return points}
function renderChart(){const el=$('threatChart');const data=threatTimeline.slice(-30);if(!data.length){el.innerHTML='<div class="empty-chart"><strong>NO THREAT ACTIVITY</strong><span>Waiting for live telemetry and detection events…</span></div>';return}const W=920,H=300,L=48,R=42,T=22,B=38,plotW=W-L-R,plotH=H-T-B;const maxBar=Math.max(1,...data.map(d=>d.newAlerts));const maxLine=Math.max(1,...data.map(d=>d.total));const n=data.length;const step=plotW/Math.max(1,n-1);const barW=Math.max(5,Math.min(18,plotW/Math.max(1,n*1.7)));const y=v=>T+plotH-(v/maxBar)*plotH;const yLine=v=>T+plotH-(v/maxLine)*plotH;const x=i=>L+i*step;let grid='';for(let i=0;i<=4;i++){const yy=T+(plotH/4)*i;const val=Math.round(maxBar-(maxBar/4)*i);grid+=`<line x1="${L}" y1="${yy}" x2="${W-R}" y2="${yy}" class="chart-grid-line"/><text x="${L-10}" y="${yy+4}" class="chart-axis" text-anchor="end">${val}</text>`}let bars='';let path='';let labels='';data.forEach((d,i)=>{const xx=x(i);const totalNew=d.normal+d.suspicious+d.malicious;const base=T+plotH;let cursor=base;if(totalNew){const segments=[['normal',d.normal],['suspicious',d.suspicious],['malicious',d.malicious]];segments.forEach(([kind,v])=>{if(!v)return;const h=(v/maxBar)*plotH;cursor-=h;bars+=`<rect x="${xx-barW/2}" y="${cursor}" width="${barW}" height="${h}" rx="3" class="threat-bar ${kind}"><title>${d.time||''}: ${v} ${kind} alert(s)</title></rect>`})}const ly=yLine(d.total);path+=(i?' L':'M')+` ${xx} ${ly}`;if(i===0||i===n-1||i%Math.max(1,Math.ceil(n/5))===0){const label=(d.time||'').split(' ')[1]||d.time||'';labels+=`<text x="${xx}" y="${H-12}" class="chart-axis" text-anchor="middle">${esc(label.slice(0,5))}</text>`}});el.innerHTML=`<svg class="threat-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Live threat activity timeline"><defs><linearGradient id="threatLineGradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#6b45ff" stop-opacity=".32"/><stop offset="100%" stop-color="#6b45ff" stop-opacity="0"/></linearGradient></defs>${grid}<line x1="${L}" y1="${T+plotH}" x2="${W-R}" y2="${T+plotH}" class="chart-axis-line"/>${bars}<path d="${path}" class="threat-line"/><path d="${path} L ${x(n-1)} ${T+plotH} L ${x(0)} ${T+plotH} Z" class="threat-area"/>${data.map((d,i)=>{const xx=x(i),ly=yLine(d.total);return `<circle cx="${xx}" cy="${ly}" r="${d.newAlerts?4:2.5}" class="threat-point"><title>${d.time||''} • Total alerts: ${d.total}</title></circle>`}).join('')}${labels}<text x="${L}" y="14" class="chart-unit">NEW ALERTS</text><text x="${W-R}" y="14" class="chart-unit" text-anchor="end">TOTAL ALERTS</text></svg>`}
function renderSeverity(alerts){const counts={critical:0,high:0,medium:0,safe:0};alerts.forEach(a=>{const k=(a.severity||'safe').toLowerCase();if(counts[k]!=null)counts[k]++});const max=Math.max(1,...Object.values(counts));$('severityBars').innerHTML=Object.entries(counts).map(([k,v])=>`<div class="sev-row"><span>${k.toUpperCase()}</span><div class="sev-track"><div class="sev-fill ${k}" style="width:${v/max*100}%"></div></div><b>${v}</b></div>`).join('')}
async function refresh(){try{const [s,a,st]=await Promise.all([api('/api/status'),api('/api/alerts'),api('/api/stats')]);const ready=s.model_ready;const running=s.capture_running; $('mFlows').textContent=st.flows;$('mPackets').textContent=st.packets;$('mThreats').textContent=st.threats;$('mModel').textContent=ready?'READY':'NOT READY';$('mModelSub').textContent=ready?'Detection engine available':'Train model to enable detection';$('captureState').textContent=running?'CAPTURE RUNNING':'MONITORING';$('heroHealth').textContent=ready?'SYSTEM OPERATIONAL':'MODEL NOT READY';$('heroTime').textContent=new Date().toLocaleTimeString();$('postureInterface').textContent=s.interface||'NOT SET';$('postureModel').textContent=ready?'READY':'NOT READY';$('rfStatus').textContent=ready?'READY':'NOT READY';$('isoStatus').textContent=ready?'READY':'NOT READY';$('sysModel').textContent=ready?'READY':'NOT READY';$('sysCapture').textContent=running?'RUNNING':'STOPPED';$('sysInterface').textContent=s.interface||'NOT SET';$('trafficState').textContent=running?'RUNNING':'STOPPED';$('trafficInterface').textContent='Interface: '+(s.interface||'NOT SET');$('tPackets').textContent=st.packets;$('tFlows').textContent=st.flows;$('tThreats').textContent=st.threats;$('aPackets').textContent=st.packets;$('aFlows').textContent=st.flows;$('aThreats').textContent=st.threats;if(lastAlertTotal===null){threatTimeline=seedThreatTimeline(a);lastAlertTotal=st.threats}else{const delta=Math.max(0,st.threats-lastAlertTotal);const now=new Date().toLocaleTimeString();const severityCounts={normal:0,suspicious:0,malicious:0};if(delta>0){a.slice(0,delta).forEach(x=>severityCounts[severityBucket(x)]++)}threatTimeline.push({time:now,newAlerts:delta,total:st.threats,normal:severityCounts.normal,suspicious:severityCounts.suspicious,malicious:severityCounts.malicious});if(threatTimeline.length>40)threatTimeline.shift();lastAlertTotal=st.threats}renderChart();renderAlerts(a);renderSeverity(a);await loadFlows()}catch(e){$('sideBackend').textContent='Error';$('heroHealth').textContent='BACKEND ERROR'}}
async function loadFlows(){try{const flows=await api('/api/flows');lastFlows=flows||[];$('flowTable').innerHTML=lastFlows.length?lastFlows.slice().reverse().map(f=>`<tr><td>${esc(f.source)}</td><td>${esc(f.destination)}</td><td>${esc(f.protocol)}</td><td>${esc(f.destination_port)}</td><td>${esc(f.packet_count)}</td><td>${Number(f.byte_count||0).toLocaleString()}</td><td>${Number(f.packets_per_sec||0).toFixed(1)} pkt/s</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No captured flows yet.</td></tr>';renderIncidents(lastAlerts);renderNetwork(lastFlows);renderDNS(lastFlows)}catch(e){}}
function renderIncidents(alerts){const high=(alerts||[]).filter(a=>['HIGH','CRITICAL'].includes((a.severity||'').toUpperCase())).length;$('incidentCount').textContent=(alerts||[]).length;$('incidentHigh').textContent=high;$('incidentOpen').textContent=high;const rows=(alerts||[]).slice(0,10);$('incidentList').innerHTML=rows.length?rows.map((a,i)=>`<div class="incident-row"><div class="incident-index">${String(i+1).padStart(2,'0')}</div><div><b>${esc(a.threat_type||'Alert')}</b><small>${esc(a.source||'—')} → ${esc(a.destination||'—')} · ${esc(a.timestamp||'')}</small></div><span class="badge ${(a.severity||'safe').toLowerCase()==='critical'?'red':(a.severity||'safe').toLowerCase()==='high'?'orange':'yellow'}">${esc(a.severity||'SAFE')}</span><strong>${esc(a.confidence??0)}%</strong></div>`).join(''):'<div class="empty">No incidents in the current session.</div>'}
function renderNetwork(flows){const src=new Set(flows.map(f=>f.source));const dst=new Set(flows.map(f=>f.destination));const proto=new Set(flows.map(f=>f.protocol));$('netSources').textContent=src.size;$('netDestinations').textContent=dst.size;$('netProtocols').textContent=proto.size;$('netFlows').textContent=flows.length}
function renderDNS(flows){const dns=flows.filter(f=>Number(f.destination_port)===53);const sources=new Set(dns.map(f=>f.source));const high=dns.filter(f=>Number(f.packets_per_sec||0)>=100);$('dnsFlows').textContent=dns.length;$('dnsSources').textContent=sources.size;$('dnsHighRate').textContent=high.length;$('dnsTable').innerHTML=dns.length?dns.slice().reverse().map(f=>{const indicator=Number(f.packets_per_sec||0)>=100?'HIGH RATE':'OBSERVED';return `<tr><td>${esc(f.source)}</td><td>${esc(f.destination)}</td><td>${esc(f.protocol)}</td><td>${esc(f.packet_count)}</td><td>${Number(f.packets_per_sec||0).toFixed(1)} pkt/s</td><td>${Number(f.byte_count||0).toLocaleString()}</td><td><span class="badge ${indicator==='HIGH RATE'?'orange':'blue'}">${indicator}</span></td></tr>`}).join(''):'<tr><td colspan="7" class="empty">No DNS flows observed yet.</td></tr>'}
async function setInterface(){try{const v=$('iface').value.trim();if(!v)return alert('Enter an interface name.');await api('/api/capture/interface',{method:'POST',body:JSON.stringify({interface:v})});refresh()}catch(e){alert(e.message)}}
async function startCapture(){try{await api('/api/capture/start',{method:'POST'});refresh()}catch(e){alert(e.message)}}async function stopCapture(){try{await api('/api/capture/stop',{method:'POST'});refresh()}catch(e){alert(e.message)}}async function demo(){try{await api('/api/analyze/demo',{method:'POST'});showPage('alerts');refresh()}catch(e){alert(e.message)}}async function clearData(){try{await api('/api/clear',{method:'POST'});refresh()}catch(e){alert(e.message)}}
$('demoValidationBtn').onclick=demo;
$('setBtn').onclick=setInterface;$('startBtn').onclick=startCapture;$('stopBtn').onclick=stopCapture;$('demoBtn').onclick=demo;$('clearBtn').onclick=clearData;$('clearBtn2').onclick=clearData;$('refreshBtn').onclick=refresh;setInterval(refresh,2000);refresh();
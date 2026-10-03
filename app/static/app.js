'use strict';

// Same-origin UI. Untrusted event fields and notes are always escaped or assigned as text.
const paths = {
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3z M12 8v5 M12 16h.01',
  events: 'M4 5h16 M4 10h16 M4 15h10 M4 20h10 M18 15v6 M15 18h6',
  rules: 'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
  report: 'M6 3h9l4 4v14H6z M14 3v5h5 M9 12h7 M9 16h7',
  upload: 'M12 16V3 M7 8l5-5 5 5 M4 16v5h16v-5',
  download: 'M12 3v13 M7 11l5 5 5-5 M4 17v4h16v-4',
  code: 'M8 6l-6 6 6 6 M16 6l6 6-6 6 M14 3l-4 18',
  external: 'M14 3h7v7 M21 3l-9 9 M10 3H3v18h18v-7',
  refresh: 'M20 7a9 9 0 10 1 10 M20 3v6h-6',
  menu: 'M3 6h18 M3 12h18 M3 18h18',
  close: 'M6 6l12 12 M6 18L18 6',
  arrow: 'M4 12h16 M15 7l5 5-5 5',
  back: 'M20 12H4 M9 7l-5 5 5 5',
  source: 'M12 2a10 10 0 100 20 10 10 0 000-20z M2 12h20 M12 2c6 5 6 15 0 20 M12 2c-6 5-6 15 0 20',
  user: 'M12 3a4 4 0 100 8 4 4 0 000-8z M4 21v-3a8 8 0 0116 0v3',
  host: 'M3 4h18v13H3z M8 21h8 M12 17v4',
  service: 'M12 3l9 5-9 5-9-5 9-5z M3 12l9 5 9-5 M3 16l9 5 9-5',
  check: 'M4 12l5 5L20 6',
  clock: 'M12 2a10 10 0 100 20 10 10 0 000-20z M12 6v6l4 2',
  search: 'M10 3a7 7 0 100 14 7 7 0 000-14z M15 15l6 6',
  lock: 'M5 10h14v11H5z M8 10V6a4 4 0 018 0v4',
  pulse: 'M2 12h5l3-8 4 16 3-8h5',
  info: 'M12 2a10 10 0 100 20 10 10 0 000-20z M12 10v7 M12 6h.01',
};
const icon = name => `<svg class='icon' aria-hidden='true' viewBox='0 0 24 24'><path d='${paths[name] || paths.shield}'/></svg>`;
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const number = value => Number(value || 0).toLocaleString('en-US');
const utcLabel = value => value ? new Date(value).toLocaleString('en-GB', {timeZone:'UTC',day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) : 'No events';
const shortTime = value => value ? new Date(value).toLocaleString('en-GB', {timeZone:'UTC',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}) : '—';
const severityBadge = severity => `<span class='badge ${escapeHTML(severity)}'><span class='severity-dot ${escapeHTML(severity)}'></span>${escapeHTML(severity)}</span>`;
const statusBadge = status => `<span class='status-badge ${escapeHTML(status)}'><span class='status-dot'></span>${escapeHTML(status)}</span>`;
const outcome = type => `<span class='event-outcome ${type === 'authentication_success' ? 'success' : 'failure'}'><span class='dot'></span>${type === 'authentication_success' ? 'Success' : 'Failure'}</span>`;
const attackHTML = (value, compact = false) => {
  const techniques = value?.mitre_attack || [];
  if (!techniques.length) return compact ? `<span class='attack-inline none'>No direct ATT&CK</span>` : `<div class='attack-row'><span class='attack-label'>MITRE ATT&CK</span><span class='attack-note'>${escapeHTML(value?.mitre_attack_note || 'No direct technique mapping.')}</span></div>`;
  const chips = techniques.map(technique => `<span class='attack-chip ${escapeHTML(technique.mapping || 'contextual')}'><strong>${escapeHTML(technique.id)}</strong>${compact ? '' : `<span>${escapeHTML(technique.name)}</span>`}</span>`).join('');
  return compact ? `<span class='attack-inline'>${chips}</span>` : `<div class='attack-row'><span class='attack-label'>MITRE ATT&CK</span><div class='attack-techniques'>${chips}</div><span class='attack-note'>${escapeHTML(value?.mitre_attack_note || '')}</span></div>`;
};
const selected = (a, b) => a === b ? ' selected' : '';
const pageSize = 25;
let meta, summary, charts = [], alertFilters = {}, alertOffset = 0, eventOffset = 0;
let eventQuery = '', eventType = '', renderRevision = 0, toastTimer;
const main = document.getElementById('main');

for (const target of document.querySelectorAll('[data-icon]')) target.innerHTML = icon(target.dataset.icon);
async function api(url, options = {}) {
  const response = await fetch(url, {...options, headers: {'X-SOC-Client':'dashboard', ...options.headers}});
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const error = await response.json();
      message = typeof error.detail === 'string' ? error.detail : (error.detail || []).map(e => `${(e.loc || []).join('.')}: ${e.msg}`).join('\n');
    } catch { /* Keep the HTTP error for unexpected non-JSON responses. */ }
    const failure = new Error(message); failure.status = response.status; throw failure;
  }
  return response.json();
}
function notify(message, isError = false) {
  const toast = document.getElementById('toast');
  toast.textContent = message; toast.className = `toast visible${isError ? ' error' : ''}`;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => toast.classList.remove('visible'), 6000);
}
function queryString(filters) {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value !== '' && value !== null && value !== undefined) parameters.set(key, value);
  return parameters.toString();
}
function destroyCharts() { charts.forEach(chart => chart.destroy()); charts = []; }
function connect(connected) {
  document.getElementById('connection-label').textContent = connected ? 'SQLite connected' : 'Connection unavailable';
  document.getElementById('connection-dot').classList.toggle('error', !connected);
}
function navigate(url) {
  history.pushState({}, '', url); document.getElementById('sidebar').classList.remove('open');
  document.getElementById('mobile-nav').setAttribute('aria-expanded','false');
  render(); window.scrollTo({top:0,behavior:'instant'});
}
function heading(eyebrow, title, subtitle, actions = '') {
  return `<div class='page-heading'><div><p class='eyebrow'>${eyebrow}</p><h1>${title}</h1><p class='subtitle'>${subtitle}</p></div><div class='heading-actions'>${actions}</div></div>`;
}
function importButton() { return `<button class='button primary' data-import>${icon('upload')}Import logs</button>`; }
function emptyState() {
  return `<div class='empty-state'>${icon('shield')}<h2>Your SOC workspace is ready</h2><p>Load the synthetic scenario library to explore seven explainable detection rules, investigate evidence, and build an analyst case.</p><button class='button primary' data-import>${icon('upload')}Load synthetic events</button></div>`;
}
function alertTable(items, compact = false) {
  return `<div class='table-scroll'><table><thead><tr><th>Severity</th><th>Detection / Rule</th><th>Source IP</th><th>Account</th><th>Last seen · UTC</th><th>Status</th><th><span class='muted'>Open</span></th></tr></thead><tbody>${items.length ? items.map(alert => `<tr><td>${severityBadge(alert.severity)}</td><td><a href='/alerts/${alert.id}' data-alert-id='${alert.id}' class='detection-link'>${escapeHTML(alert.rule_name)}</a><span class='detection-code'>${escapeHTML(alert.rule_id)} <span class='muted'>/</span> ${escapeHTML(alert.display_id)} ${compact ? '' : `· ${alert.evidence_count} events`} ${attackHTML(alert, true)}</span></td><td class='mono'>${escapeHTML(alert.source_ip)}</td><td>${escapeHTML(alert.username)}</td><td class='mono'>${compact ? shortTime(alert.last_seen) : utcLabel(alert.last_seen)}</td><td>${statusBadge(alert.status)}</td><td><a class='row-arrow' href='/alerts/${alert.id}' data-alert-id='${alert.id}' aria-label='Investigate ${escapeHTML(alert.display_id)}'>${icon('arrow')}</a></td></tr>`).join('') : `<tr><td colspan='7' class='table-empty'>No alerts match this query. Adjust or reset the filters.</td></tr>`}</tbody></table></div>`;
}
function pagination(total, offset, entity) {
  return `<div class='table-footer'><span>${total ? `${number(offset + 1)}–${number(Math.min(total, offset + pageSize))} of ${number(total)}` : '0 results'}</span><div class='pagination'><button class='button small ghost' data-page='${entity}' data-offset='${Math.max(0, offset - pageSize)}' ${offset === 0 ? 'disabled' : ''}>Previous</button><button class='button small ghost' data-page='${entity}' data-offset='${offset + pageSize}' ${offset + pageSize >= total ? 'disabled' : ''}>Next</button></div></div>`;
}
function overviewHTML(alerts) {
  const s = summary;
  const cards = [
    ['Total events',s.total_events,'events','Normalized authentication events',''],
    ['Alerts',s.total_alerts,'shield',`${s.statuses.New + s.statuses.Investigating} open analyst cases`,'alerts'],
    ['Critical alerts',s.critical_alerts,'pulse','Success after repeated failures','critical'],
    ['Failed logins',s.failed_logins,'lock',`${s.total_events ? (s.failed_logins/s.total_events*100).toFixed(1) : 0}% of authentication events`,''],
    ['Unique sources',s.unique_sources,'source','Documentation-range IPs only',''],
  ];
  const severityLegend = Object.entries(s.severity).map(([key, value]) => `<div class='legend-row'><span class='severity-dot ${key}'></span>${key.charAt(0).toUpperCase()+key.slice(1)}<strong>${value}</strong></div>`).join('');
  return heading('SECURITY OPERATIONS / TELEMETRY OVERVIEW','Every signal. Clear context.','Investigate authentication activity with explainable detections and an evidence-driven workflow.',`<a class='button' href='/#reports'>${icon('download')}Export report</a>${importButton()}`) +
    (s.total_events ? `<div class='dataset-strip'><span>${icon('clock')} <strong>All ingested data · ${utcLabel(s.first_event)} — ${utcLabel(s.last_event)} UTC</strong></span><div class='pipeline'><span>Ingestion</span>${icon('arrow')}<span>Correlation</span>${icon('arrow')}<span>Analyst triage</span></div></div><div class='stats-grid'>${cards.map(([label, count, symbol, foot, kind]) => `<section class='stat-card ${kind}'><div class='stat-top'><span>${label}</span>${icon(symbol)}</div><div class='stat-number' data-stat='${label}'>${number(count)}</div><div class='stat-bottom'><span class='dot'></span>${foot}</div></section>`).join('')}</div>
    <div class='chart-row'><section class='panel'><div class='panel-header'><h2>Authentication activity</h2><span class='meta'>UTC · ${s.bucket_seconds/3600}H BUCKETS</span></div><p class='panel-subtitle'>Event volume across the full ingested dataset</p><div class='chart-body'><canvas id='timeline-chart' role='img' aria-label='Authentication successes and failures over time'></canvas></div><div class='chart-legend'><span><i class='legend-dot success'></i>Successful logins</span><span><i class='legend-dot failure'></i>Failed logins</span></div></section>
    <section class='panel'><div class='panel-header'><h2>Alert severity</h2><span class='meta'>ALL STATUSES</span></div><p class='panel-subtitle'>Detection priority distribution</p><div class='severity-content'><div class='donut-wrap'><canvas id='severity-chart' role='img' aria-label='Alert severity distribution'></canvas><div class='donut-center'><strong>${s.total_alerts}</strong><span>TOTAL ALERTS</span></div></div><div class='legend-list'>${severityLegend}</div></div><div class='panel-foot'><span>Investigation required</span><strong>${s.critical_alerts} critical detections</strong></div></section></div>
    <div class='chart-row three'><section class='panel'><div class='panel-header'><h2>Top source IPs</h2><span class='meta'>TOP 5</span></div><p class='panel-subtitle'>All authentication events per source</p><div class='chart-body compact'><canvas id='sources-chart' role='img' aria-label='Top five source IPs by event count'></canvas></div></section>
    <section class='panel'><div class='panel-header'><h2>Authentication outcomes</h2><span class='meta'>SUCCESS / FAILURE</span></div><p class='panel-subtitle'>Authentication result breakdown</p><div class='auth-chart'><div class='donut-wrap small'><canvas id='auth-chart' role='img' aria-label='Successful versus failed authentication'></canvas><div class='donut-center'><strong>${(s.successful_logins/s.total_events*100).toFixed(0)}%</strong><span>SUCCESS</span></div></div><div class='auth-labels'><div><p><i class='legend-dot success'></i>Success</p><strong>${number(s.successful_logins)}</strong></div><div><p><i class='legend-dot failure'></i>Failure</p><strong class='failure-count'>${number(s.failed_logins)}</strong></div></div></div></section>
    <section class='panel'><div class='panel-header'><h2>Most targeted accounts</h2><span class='meta'>TOP 5</span></div><p class='panel-subtitle'>Failed authentication events per account</p><div class='chart-body compact'><canvas id='accounts-chart' role='img' aria-label='Most targeted accounts by failed logins'></canvas></div></section></div>
    <section class='panel table-panel'><div class='panel-header'><div class='table-caption'><h2>Priority investigation queue</h2><span class='count-chip'>${s.statuses.New + s.statuses.Investigating} OPEN</span></div><a class='text-link' href='/#alerts'>View all alerts ${icon('arrow')}</a></div>${alertTable(alerts.items, true)}<div class='panel-foot'><span>Sorted by severity, then most recent evidence</span><strong>Evidence & recommendations in every case</strong></div></section>` : emptyState());
}
function chartSetup() {
  const Chart = window.Chart;
  Chart.defaults.color = '#778ba5'; Chart.defaults.font.family = 'Inter, Segoe UI, Arial, sans-serif'; Chart.defaults.font.size = 9;
  const shared = {responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'#0b1524',titleColor:'#edf4fb',bodyColor:'#a8b8cc',borderColor:'#314760',borderWidth:1,padding:10}}};
  const cartesian = {x:{grid:{color:'#2a3d5660',drawTicks:false},border:{display:false},ticks:{maxTicksLimit:9,maxRotation:0,padding:9}},y:{beginAtZero:true,border:{display:false},grid:{color:'#2a3d5660',drawTicks:false},ticks:{maxTicksLimit:5,padding:8,precision:0}}};
  const add = (id, config) => charts.push(new Chart(document.getElementById(id), config));
  const rows = summary.events_over_time;
  add('timeline-chart',{type:'line',data:{labels:rows.map(row => new Date(row.timestamp).toLocaleString('en-GB',{timeZone:'UTC',hour:'2-digit',minute:'2-digit',hour12:false})),datasets:[{label:'Success',data:rows.map(row=>row.success),borderColor:'#63dbc8',backgroundColor:'#63dbc812',fill:true,tension:.32,borderWidth:2,pointRadius:0,pointHoverRadius:4},{label:'Failure',data:rows.map(row=>row.failure),borderColor:'#71b7ea',backgroundColor:'#71b7ea0b',fill:true,tension:.32,borderWidth:2,pointRadius:0,pointHoverRadius:4}]},options:{...shared,scales:cartesian,interaction:{mode:'index',intersect:false}}});
  const doughnut = (id,labels,values,colors) => add(id,{type:'doughnut',data:{labels,datasets:[{data:values,backgroundColor:colors,borderWidth:0,spacing:4,borderRadius:2}]},options:{...shared,cutout:'80%'}});
  doughnut('severity-chart',['Critical','High','Medium','Low'],Object.values(summary.severity),['#ff7d99','#f4ad69','#e7c875','#7fa9e8']);
  doughnut('auth-chart',['Success','Failure'],[summary.successful_logins,summary.failed_logins],['#63dbc8','#71b7ea']);
  const horizontal = (id, rows, color) => add(id,{type:'bar',data:{labels:rows.map(row=>row.label),datasets:[{label:'Events',data:rows.map(row=>row.count),backgroundColor:color,borderRadius:3,barThickness:12}]},options:{...shared,indexAxis:'y',scales:{x:{...cartesian.x,beginAtZero:true,ticks:{maxTicksLimit:5,precision:0}},y:{border:{display:false},grid:{display:false},ticks:{color:'#93a9c5',font:{family:'Consolas, monospace',size:9}}}}}});
  horizontal('sources-chart',summary.top_sources,['#4d9f98','#4d9f98','#4d9f98','#4d9f98','#4d9f98']);
  horizontal('accounts-chart',summary.targeted_accounts,'#7383b8');
}
function alertFilterForm() {
  const f = alertFilters;
  const localInput = value => { if (!value) return ''; const date = new Date(value); return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16); };
  return `<form class='filters' id='alert-filters'><div class='filter-grid'>
    <div class='field'><label for='filter-q'>Search detection, host, or service</label><input id='filter-q' name='q' placeholder='Search the alert queue…' value='${escapeHTML(f.q || '')}'></div>
    <div class='field'><label for='filter-severity'>Severity</label><select id='filter-severity' name='severity'><option value=''>All severities</option>${['critical','high','medium','low'].map(value=>`<option value='${value}'${selected(f.severity,value)}>${value.charAt(0).toUpperCase()+value.slice(1)}</option>`).join('')}</select></div>
    <div class='field'><label for='filter-status'>Analyst status</label><select id='filter-status' name='status'><option value=''>All statuses</option>${['New','Investigating','Closed'].map(value=>`<option${selected(f.status,value)}>${value}</option>`).join('')}</select></div>
    <div class='field'><label for='filter-rule'>Detection rule</label><select id='filter-rule' name='rule_id'><option value=''>All rules</option>${meta.rules.map(rule=>`<option value='${rule.id}'${selected(f.rule_id,rule.id)}>${rule.id} · ${escapeHTML(rule.name)}</option>`).join('')}</select></div>
    <div class='field'><label for='filter-source'>Source IP · exact match</label><input id='filter-source' name='source_ip' placeholder='198.51.100.42' value='${escapeHTML(f.source_ip || '')}'></div>
    <div class='field'><label for='filter-user'>Username · exact match</label><input id='filter-user' name='username' placeholder='muhammed' value='${escapeHTML(f.username || '')}'></div>
    <div class='field'><label for='filter-start'>From · your local timezone</label><input id='filter-start' name='start' type='datetime-local' value='${localInput(f.start)}'></div>
    <div class='field'><label for='filter-end'>Until · your local timezone</label><input id='filter-end' name='end' type='datetime-local' value='${localInput(f.end)}'></div>
    <div class='filter-actions'><button class='button primary' type='submit'>${icon('search')}Apply filters</button><button class='button ghost' type='button' id='reset-alert-filters'>Reset</button></div></div>
    <p class='filter-hint'>Source and account filters inspect all matched evidence. Date filters use the alert’s last matched event. Display timestamps are UTC.</p><p id='filter-error' class='inline-error' role='alert'></p></form>`;
}
function alertsHTML(results) {
  return heading('DETECTION & TRIAGE','Alert investigation queue','Prioritize detections, inspect the evidence, and record your investigation.',`<a href='/#reports' class='button'>${icon('download')}Export filtered queue</a>`) + alertFilterForm() + `<div class='result-heading'><span><strong>${number(results.total)}</strong> matching alerts</span><span>Priority first · latest evidence next</span></div><section class='panel table-panel'>${alertTable(results.items)}${pagination(results.total,alertOffset,'alerts')}</section>`;
}
function eventsHTML(results) {
  return heading('INGESTION & NORMALIZATION','Event explorer','Search the normalized authentication records that support every detection.',importButton()) + `<form id='event-filters' class='filters'><div class='filter-grid'><div class='field'><label for='event-q'>Search IP, account, host, service, or event ID</label><input id='event-q' name='q' placeholder='Search normalized events…' value='${escapeHTML(eventQuery)}'></div><div class='field'><label for='event-type'>Authentication outcome</label><select id='event-type' name='event_type'><option value=''>All outcomes</option><option value='authentication_success'${selected(eventType,'authentication_success')}>Success</option><option value='authentication_failure'${selected(eventType,'authentication_failure')}>Failure</option></select></div><div class='filter-actions'><button class='button primary' type='submit'>${icon('search')}Search events</button><button type='button' class='button ghost' id='reset-events'>Reset</button></div></div></form><div class='result-heading'><span>${number(results.total)} normalized events</span><span>Synthetic data · UTC timestamps</span></div><section class='panel table-panel'><div class='table-scroll'><table><thead><tr><th>Timestamp · UTC</th><th>Outcome</th><th>Source IP</th><th>Account</th><th>Host</th><th>Service</th><th>Event ID</th></tr></thead><tbody>${results.items.length ? results.items.map(event=>`<tr><td class='mono'>${utcLabel(event.timestamp)}</td><td>${outcome(event.event_type)}</td><td class='mono'>${escapeHTML(event.source_ip)}</td><td>${escapeHTML(event.username)}</td><td class='mono'>${escapeHTML(event.hostname)}</td><td>${escapeHTML(event.service)}</td><td class='mono muted'>${escapeHTML(event.event_id)}</td></tr>`).join('') : `<tr><td colspan='7' class='table-empty'>No events match this query.</td></tr>`}</tbody></table></div>${pagination(results.total,eventOffset,'events')}</section>${summary.latest_import ? `<div class='panel import-history'>${icon('check')}<span>Last import: <strong>${escapeHTML(summary.latest_import.filename)}</strong> · ${number(summary.latest_import.inserted)} new events · ${number(summary.latest_import.duplicates)} duplicates skipped · ${summary.latest_import.duration_ms} ms</span></div>` : ''}`;
}
function caseHTML(alert) {
  const fields = [['SOURCE IP','source_ip','source'],['ACCOUNT','username','user'],['HOST','hostname','host'],['SERVICE','service','service']];
  return `<a href='/#alerts' class='back-link'>${icon('back')}Back to alert queue</a><div class='page-heading case-heading'><div><div class='case-kicker'>${severityBadge(alert.severity)}<span>${escapeHTML(alert.display_id)}</span><span>/</span><span>${escapeHTML(alert.rule_id)} · RULE v${escapeHTML(alert.rule_version)}</span></div><h1>${escapeHTML(alert.rule_name)}</h1><p class='case-meta'>First evidence ${utcLabel(alert.first_seen)} UTC <span class='muted'>→</span> Last evidence ${utcLabel(alert.last_seen)} UTC</p></div>${statusBadge(alert.status)}</div>
    <div class='case-layout'><div class='case-main'><div class='identity-grid'>${fields.map(([label,field,symbol])=>`<div class='identity-card'><div class='label'>${icon(symbol)}${label}</div><strong class='mono'>${escapeHTML(alert[field])}</strong></div>`).join('')}</div>
    <section class='panel narrative-panel'><div class='panel-header'><h2>Detection narrative</h2><span class='count-chip'>${alert.evidence_count} EVIDENCE EVENTS</span></div><div class='panel-content'><p>${escapeHTML(alert.explanation)}</p>${attackHTML(alert)}<div class='recommendation'><h3>${icon('shield')}INVESTIGATION RECOMMENDATION</h3><p>${escapeHTML(alert.recommendation)}</p></div></div><details class='config-details'><summary>Detection configuration & provenance</summary><pre>${escapeHTML(JSON.stringify(alert.rule_parameters,null,2))}</pre><p class='snapshot-hash'>Configuration SHA-256: ${escapeHTML(alert.config_hash)}</p></details></section>
    <section class='panel table-panel'><div class='panel-header'><h2>Matched authentication evidence</h2><span class='meta'>TIME ORDERED · UTC</span></div><p class='evidence-note'>Each row is the original normalized event. Multi-account and volume alerts show the latest trigger in the identity cards.</p><div class='table-scroll'><table class='evidence-table'><thead><tr><th>Timestamp</th><th>Outcome</th><th>Source IP</th><th>Account</th><th>Host / Service</th><th>Event ID</th></tr></thead><tbody>${alert.evidence.map(event=>`<tr><td class='mono'>${utcLabel(event.timestamp)}</td><td>${outcome(event.event_type)}</td><td class='mono'>${escapeHTML(event.source_ip)}</td><td>${escapeHTML(event.username)}</td><td class='mono'>${escapeHTML(event.hostname)} / ${escapeHTML(event.service)}</td><td class='mono muted'>${escapeHTML(event.event_id)}</td></tr>`).join('')}</tbody></table></div></section></div>
    <aside class='case-sidebar'><section class='panel'><div class='panel-header'><h2>Analyst workspace</h2><span class='meta'>REVISION ${alert.version}</span></div><form class='case-form' id='case-form' data-id='${alert.id}' data-version='${alert.version}'><div class='field'><label for='case-status'>Investigation status</label><select id='case-status' name='status'>${['New','Investigating','Closed'].map(value=>`<option${selected(alert.status,value)}>${value}</option>`).join('')}</select></div><div class='field'><label for='case-note'>Append an analyst note</label><textarea id='case-note' name='note' maxlength='2000' placeholder='Record what you checked, your conclusion, and the next action…'></textarea></div><p class='muted filter-hint'>Notes are retained in the case journal. Record conclusions supported by the evidence.</p><p class='inline-error' id='case-error' role='alert'></p><button class='button primary full-width' id='save-case' type='submit'>${icon('check')}Save investigation</button><button type='button' class='button ghost' id='reload-case'>Reload case</button></form></section><section class='panel'><div class='panel-header'><h2>Case activity</h2><span class='count-chip'>${alert.activity.length}</span></div><div class='activity-list'>${alert.activity.map(activity=>`<div class='activity-item ${escapeHTML(activity.kind)}'><span class='activity-meta'>${utcLabel(activity.timestamp)} UTC · ${escapeHTML(activity.analyst)}</span><p>${escapeHTML(activity.content)}</p></div>`).join('')}</div></section></aside></div>`;
}
function rulesHTML() {
  return heading('EXPLAINABLE CORRELATION','Detection rule library','Seven transparent rules. Every finding links directly to the events and parameters that produced it.',`<button class='button' id='run-detections'>${icon('refresh')}Replay detections</button>`) + `<div class='panel rule-banner'>${icon('info')}<span>Rolling windows are inclusive. Rate matches are grouped per entity into ${meta.config.aggregation_seconds/60}-minute UTC episodes. Privileged and out-of-hours logins are contextual signals; the watchlist is synthetic. These rules produce triage hypotheses.</span></div><div class='rules-list'>${meta.rules.map(rule=>`<article class='panel rule-card'><div class='panel-header'><div class='rule-title'><p>${rule.id} / v${escapeHTML(rule.version)}</p><h2>${escapeHTML(rule.name)}</h2></div>${severityBadge(rule.severity)}</div><div class='panel-content'><p>${escapeHTML(rule.description)}</p><div class='rule-parameters'>${escapeHTML(rule.parameters)}</div>${attackHTML(rule)}<p class='rule-small-heading'>COMMON FALSE POSITIVES</p><p>${escapeHTML(rule.false_positives)}</p><div class='recommendation'><h3>ANALYST NEXT STEP</h3><p>${escapeHTML(rule.recommendation)}</p></div></div></article>`).join('')}</div>`;
}
function reportsHTML() {
  const scope = Object.keys(alertFilters).length ? Object.entries(alertFilters).map(([key,value])=>`${key}: ${value}`).join(' · ') : 'All historical alerts · all severities · all statuses';
  const formats = [['html','HTML investigation report','A standalone report with evidence tables, recommendations, and the analyst journal. Open locally or print to PDF.','report','Download HTML'],['json','JSON evidence export','Structured case records with matched events, configuration snapshots, and activity history for reproducible review.','code','Download JSON'],['markdown','Markdown case report','A readable report for GitHub documentation, handovers, and your portfolio investigation write-up.','events','Download Markdown']];
  return heading('DOCUMENTATION & HANDOVER','Reports that carry the evidence.','Export complete investigations with their context, rule provenance, and analyst decisions.') + `<section class='panel scope-panel'><h2>Current report scope</h2><p id='report-scope'>${escapeHTML(scope)}</p><p class='filter-hint'>Alert filters are carried over from the alert queue. Dataset statistics cover the full ingested dataset. Exports include every matching alert, across all result pages.</p><div class='report-scope-actions'><a href='/#alerts' class='button small ghost'>Adjust filters</a><button id='clear-report-scope' class='button small ghost'>Use all alerts</button></div></section><div class='report-grid'>${formats.map(([format,title,description,symbol,label])=>`<article class='panel report-card'><div class='report-icon'>${icon(symbol)}</div><h2>${title}</h2><p>${description}</p><a class='button primary' data-report='${format}' href='/api/reports/${format}?${queryString(alertFilters)}'>${icon('download')}${label}</a></article>`).join('')}</div><section class='panel report-checklist'><h2>Included in every report</h2><ul>${['Rule ID, severity, analyst status, and MITRE ATT&CK mapping','Full matched authentication evidence','Detection explanation and recommendation','Persistent analyst notes and status history','Rule configuration snapshot and SHA-256','Synthetic-data scope and generation time'].map(text=>`<li>${icon('check')}${text}</li>`).join('')}</ul></section>`;
}
async function render() {
  const revision = ++renderRevision;
  const detailMatch = location.pathname.match(/^\/alerts\/(\d+)$/);
  const view = detailMatch ? 'detail' : (location.hash.slice(1) || 'overview');
  const title = {overview:'Overview',alerts:'Alert queue',events:'Event explorer',rules:'Detection rules',reports:'Reports & exports',detail:'Alert investigation'}[view] || 'Overview';
  document.getElementById('breadcrumb-view').textContent = title;
  document.querySelectorAll('nav a').forEach(link=>link.classList.toggle('active',link.dataset.view === (view === 'detail' ? 'alerts' : view)));
  try {
    const [newMeta, newSummary] = await Promise.all([api('/api/meta'),api('/api/dashboard')]);
    let data;
    if (view === 'detail') data = await api(`/api/alerts/${detailMatch[1]}`);
    else if (view === 'alerts') data = await api(`/api/alerts?${queryString({...alertFilters,limit:pageSize,offset:alertOffset})}`);
    else if (view === 'events') data = await api(`/api/events?${queryString({q:eventQuery,event_type:eventType,limit:pageSize,offset:eventOffset})}`);
    else if (!['rules','reports'].includes(view)) {
      const priority = await api('/api/alerts?limit=100');
      data = {items:priority.items.filter(alert=>alert.status !== 'Closed').slice(0,5)};
    }
    if (revision !== renderRevision) return;
    meta = newMeta; summary = newSummary; connect(true);
    document.getElementById('nav-alert-count').textContent = summary.statuses.New + summary.statuses.Investigating;
    destroyCharts();
    main.innerHTML = view === 'detail' ? caseHTML(data) : view === 'alerts' ? alertsHTML(data) : view === 'events' ? eventsHTML(data) : view === 'rules' ? rulesHTML() : view === 'reports' ? reportsHTML() : overviewHTML(data);
    if (!['alerts','events','detail','rules','reports'].includes(view) && summary.total_events) chartSetup();
    main.dataset.ready = view;
  } catch (error) {
    if (revision !== renderRevision) return;
    connect(false); destroyCharts(); main.innerHTML = `<div class='error-state'><h2>${error.status === 404 ? 'Alert not found' : 'Workspace could not load'}</h2><p>${escapeHTML(error.message)}</p><button class='button' data-retry>${icon('refresh')}Retry</button></div>`;
  }
}
function showImport() {
  document.getElementById('import-error').textContent = '';
  document.getElementById('import-dialog').showModal();
}
function importBusy(busy) {
  for (const id of ['import-submit','load-demo','close-import']) document.getElementById(id).disabled = busy;
  document.getElementById('import-submit').textContent = busy ? 'Validating & correlating…' : 'Validate & import';
}
async function importEvents(options, endpoint) {
  importBusy(true); document.getElementById('import-error').textContent = '';
  try {
    const result = await api(endpoint,options);
    document.getElementById('import-dialog').close();
    notify(`${number(result.imported)} events imported · ${number(result.duplicates)} duplicates skipped · ${result.alerts_created} new alerts`);
    await render();
  } catch (error) { document.getElementById('import-error').textContent = error.message; }
  finally { importBusy(false); }
}
document.getElementById('sidebar-import').addEventListener('click',showImport);
document.getElementById('close-import').addEventListener('click',()=>document.getElementById('import-dialog').close());
document.getElementById('load-demo').addEventListener('click',()=>importEvents({method:'POST'},'/api/demo'));
document.getElementById('import-form').addEventListener('submit',event=>{
  event.preventDefault(); const file = document.getElementById('log-file').files[0];
  if (file && file.size > 5*1024*1024) { document.getElementById('import-error').textContent = 'Maximum file size is 5 MiB'; return; }
  importEvents({method:'POST',body:new FormData(event.target)},'/api/ingest');
});
document.getElementById('log-file').addEventListener('change',event=>{
  document.getElementById('file-label').textContent = event.target.files[0]?.name || 'CSV or JSON · up to 5 MiB · 5,000 events';
});
document.getElementById('refresh').addEventListener('click',()=>render());
document.getElementById('mobile-nav').addEventListener('click',event=>{
  const opened = document.getElementById('sidebar').classList.toggle('open'); event.currentTarget.setAttribute('aria-expanded',String(opened));
});
document.addEventListener('click',async event=>{
  const target = event.target.closest('a,button'); if (!target) return;
  if (target.hasAttribute('data-import')) showImport();
  if (target.hasAttribute('data-retry') || target.id === 'reload-case') render();
  if (target.id === 'reset-alert-filters' || target.id === 'clear-report-scope') { alertFilters = {}; alertOffset = 0; render(); }
  if (target.id === 'reset-events') { eventQuery = ''; eventType = ''; eventOffset = 0; render(); }
  if (target.dataset.page) { if (target.dataset.page === 'alerts') alertOffset = Number(target.dataset.offset); else eventOffset = Number(target.dataset.offset); render(); }
  if (target.id === 'run-detections') {
    target.disabled = true;
    try { const result = await api('/api/detections/run',{method:'POST'}); notify(`Replay complete · ${result.matches} matches · ${result.alerts_created} new alerts`); await render(); }
    catch(error) { notify(error.message,true); target.disabled = false; }
  }
  if (target.tagName === 'A' && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
    const href = target.getAttribute('href');
    if (href?.startsWith('/#') || target.dataset.alertId) { event.preventDefault(); navigate(href); }
  }
});
document.addEventListener('submit',async event=>{
  if (event.target.id === 'alert-filters') {
    event.preventDefault(); const values = Object.fromEntries(new FormData(event.target));
    for (const key of ['start','end']) if (values[key]) values[key] = new Date(values[key]).toISOString();
    if (values.start && values.end && values.start > values.end) { document.getElementById('filter-error').textContent = 'From must be before or equal to Until.'; return; }
    const filters = Object.fromEntries(Object.entries(values).filter(([,value])=>value));
    try { await api(`/api/alerts?${queryString({...filters,limit:1})}`); alertFilters = filters; alertOffset = 0; render(); }
    catch(error) { document.getElementById('filter-error').textContent = error.message; }
  }
  if (event.target.id === 'event-filters') {
    event.preventDefault(); const values = Object.fromEntries(new FormData(event.target));
    eventQuery = values.q; eventType = values.event_type; eventOffset = 0; render();
  }
  if (event.target.id === 'case-form') {
    event.preventDefault(); const form = event.target; const values = Object.fromEntries(new FormData(form));
    const button = document.getElementById('save-case'); button.disabled = true;
    try {
      await api(`/api/alerts/${form.dataset.id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({version:Number(form.dataset.version),status:values.status,note:values.note || null})});
      notify('Investigation saved to the case journal.'); await render();
    } catch(error) { document.getElementById('case-error').textContent = error.message; button.disabled = false; }
  }
});
window.addEventListener('popstate',render);
window.addEventListener('hashchange',render);
render();

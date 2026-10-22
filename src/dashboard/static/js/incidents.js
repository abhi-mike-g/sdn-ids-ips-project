async function loadIncidents() {
    const summary = document.getElementById('incident-summary');
    try {
        const response = await fetch('/api/incidents');
        if (!response.ok) throw new Error('Orchestrator unavailable');
        const incidents = await response.json();
        const tbody = document.getElementById('incident-rows');
        tbody.replaceChildren();
        for (const incident of incidents) {
            const tr = document.createElement('tr');
            const values = [incident.src_ip, incident.alert_count, JSON.parse(incident.stride).join(', '),
                incident.action, incident.state, incident.mitigation_latency_ms == null ? 'Not measured' :
                incident.mitigation_latency_ms.toFixed(1) + ' ms'];
            for (const value of values) {
                const td = document.createElement('td');
                td.textContent = value;
                tr.append(td);
            }
            const actions = document.createElement('td');
            for (const [action, label] of [['resolve', 'Resolve'], ['false_positive', 'False positive']]) {
                const button = document.createElement('button');
                button.className = 'btn btn-sm btn-outline-primary me-1';
                button.textContent = label;
                button.disabled = ['resolved', 'false_positive'].includes(incident.state);
                button.onclick = async () => {
                    const result = await fetch('/api/incidents/' + encodeURIComponent(incident.id) + '/' + action, {method: 'POST'});
                    if (!result.ok) {
                        const error = await result.json();
                        alert(error.error || 'Action failed');
                    }
                    await loadIncidents();
                };
                actions.append(button);
            }
            tr.append(actions);
            tbody.append(tr);
        }
        summary.textContent = incidents.length + ' incidents. Confidence values are policy priors, not measured accuracy.';
    } catch (error) { summary.textContent = error.message; }
}
document.addEventListener('DOMContentLoaded', () => {
    loadIncidents();
    setInterval(loadIncidents, 3000);
});

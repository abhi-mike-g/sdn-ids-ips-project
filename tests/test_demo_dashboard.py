from pathlib import Path

from src.demo import build_demo


def test_replay_dashboard_has_diverse_alerts_topology_and_metrics(tmp_path):
    replay = Path(__file__).parents[1] / 'orchestrator' / 'demo_scenarios.jsonl'
    app, store, count = build_demo(str(replay), tmp_path)
    client = app.test_client()

    assert count >= 15
    topology = client.get('/api/topology').get_json()
    assert len([node for node in topology['nodes'] if node['type'] == 'host']) >= 8
    assert len(topology['flows']) >= 10
    summary = client.get('/api/security-summary').get_json()
    assert summary['targets'] >= 4
    assert len(summary['alert_families']) >= 5
    assert {row['port'] for row in summary['targeted_ports']} >= {22, 53, 80, 1883, 3306}
    assert client.get('/api/flows').get_json() == topology['flows']
    assert client.get('/briefing').status_code == 200
    assert client.get('/metrics').status_code == 200

    home = client.get('/').get_data(as_text=True)
    assert 'SNID&amp;PSS' in home
    assert 'id="theme-toggle"' in home
    assert 'href="/briefing"' not in home.split('</nav>', 1)[0]
    assert home.index('id="attackTypesChart"') < home.index('Open project briefing')

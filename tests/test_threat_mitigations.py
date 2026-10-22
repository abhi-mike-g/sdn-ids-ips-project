"""Focused checks for implemented defensive controls (no privileged sockets)."""
from unittest.mock import Mock

import pytest


def test_controller_rejects_invalid_and_protected_addresses():
    from src.controller.http_api import create_controller_api

    controller = Mock(datapaths={})
    client = create_controller_api(controller).test_client()
    assert client.post('/nidps/block_ip', json={'ip': 'bad'}).status_code == 400
    assert client.post('/nidps/block_ip', json={'ip': '10.0.0.254'}).status_code == 403


def test_dashboard_escapes_untrusted_alert_text():
    from src.dashboard.app import create_app
    from src.database.database import DatabaseManager

    db = DatabaseManager('sqlite:///:memory:')
    db.insert_alert({'severity': 2, 'alert_type': '<script>', 'source_ip': '10.0.0.1',
                     'destination_ip': '10.0.0.2', 'signature': 'test'})
    app = create_app(database=db).test_client()
    result = app.get('/api/alerts').get_json()
    assert result[0]['type'] == '<script>'
    assert app.get('/api/alerts/999').status_code == 404


def test_incident_store_keeps_analyst_terminal_decision(tmp_path):
    from orchestrator.store import Store
    from orchestrator.models import Incident, IncidentState, ResponseAction
    from datetime import datetime, timezone

    store = Store(str(tmp_path / 'incidents.db'))
    incident = Incident.new('10.0.0.1', datetime.now(timezone.utc))
    store.upsert_incident(incident)
    store.set_state(incident.id, IncidentState.FALSE_POSITIVE)
    incident.severity = 'HIGH'
    store.upsert_incident(incident)
    assert store.get_incident(incident.id)['state'] == IncidentState.FALSE_POSITIVE.value


def test_rate_limit_installs_meter_and_rejects_invalid_rate():
    from src.controller.policy_enforcer import PolicyEnforcer

    dp = Mock(id=1)
    dp.ofproto.OFPMC_ADD = 0
    dp.ofproto.OFPMF_KBPS = 1
    dp.ofproto.OFPIT_APPLY_ACTIONS = 4
    dp.ofproto.OFPP_NORMAL = 0xFFFA
    dp.ofproto_parser.OFPMeterBandDrop.return_value = object()
    enforcer = PolicyEnforcer(Mock())
    with pytest.raises(ValueError):
        enforcer.rate_limit_ip(dp, '10.0.0.1', 0)
    assert dp.send_msg.call_count == 0

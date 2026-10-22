from sqlalchemy import create_engine, desc, event, func
from sqlalchemy.engine import make_url
from sqlalchemy.pool import StaticPool
from pathlib import Path
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager
from .models import Base, Alert, FlowRule, NetworkFlow, SystemMetrics
from ..utils.config import Config
import json

class DatabaseManager:
    def __init__(self, url=None):
        self.config = Config()
        url = make_url(url or self.config.get('database.url', 'sqlite:///logs/nidps.db'))
        options = {}
        if url.drivername == 'sqlite':
            options['connect_args'] = {'check_same_thread': False, 'timeout': 30}
            if url.database in (None, '', ':memory:'):
                options['poolclass'] = StaticPool
            else:
                path = Path(url.database)
                if not path.is_absolute():
                    path = self.config.root / path
                path.parent.mkdir(parents=True, exist_ok=True)
                url = url.set(database=str(path))
        self.engine = create_engine(
            url,
            echo=False,
            pool_pre_ping=True,
            **options
        )
        if url.drivername == 'sqlite':
            @event.listens_for(self.engine, 'connect')
            def configure_sqlite(connection, _):
                connection.execute('PRAGMA journal_mode=WAL')
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(bind=self.engine, expire_on_commit=False))
    
    @contextmanager
    def session_scope(self):
        """Provide a transactional scope"""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            self.Session.remove()
    
    def insert_alert(self, alert_data):
        """Insert a new alert"""
        with self.session_scope() as session:
            alert = Alert(**alert_data)
            session.add(alert)
            session.flush()
            return alert.id
    
    def get_recent_alerts(self, limit=100, severity=None, after_id=None):
        """Get recent alerts"""
        with self.session_scope() as session:
            query = session.query(Alert).order_by(desc(Alert.timestamp))
            if severity:
                query = query.filter(Alert.severity <= severity)
            if after_id is not None:
                query = query.filter(Alert.id > after_id).order_by(None).order_by(Alert.id)
            return query.limit(limit).all()
    
    def insert_flow_rule(self, rule_data):
        """Insert flow rule"""
        with self.session_scope() as session:
            rule = FlowRule(**rule_data)
            session.add(rule)
            session.flush()
            return rule.id
    
    def get_active_flow_rules(self, switch_id=None):
        """Get active flow rules"""
        with self.session_scope() as session:
            query = session.query(FlowRule).filter(FlowRule.active == True)
            from datetime import datetime
            query = query.filter((FlowRule.expires_at == None) | (FlowRule.expires_at > datetime.utcnow()))
            if switch_id:
                query = query.filter(FlowRule.switch_id == switch_id)
            return query.all()
    
    def insert_network_flow(self, flow_data):
        """Insert network flow record"""
        with self.session_scope() as session:
            flow = NetworkFlow(**flow_data)
            session.add(flow)
            session.flush()
            return flow.id
    
    def insert_metrics(self, metrics_data):
        """Insert system metrics"""
        with self.session_scope() as session:
            metrics = SystemMetrics(**metrics_data)
            session.add(metrics)
            session.flush()
            return metrics.id
    
    def get_metrics_history(self, hours=1):
        """Get metrics history"""
        from datetime import datetime, timedelta
        with self.session_scope() as session:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            return session.query(SystemMetrics)\
                .filter(SystemMetrics.timestamp >= cutoff)\
                .order_by(SystemMetrics.timestamp)\
                .all()

    def get_alert(self, alert_id):
        with self.session_scope() as session:
            return session.get(Alert, alert_id)

    def clear_alerts(self):
        with self.session_scope() as session:
            return session.query(Alert).delete()

    def latest_alert_id(self):
        with self.session_scope() as session:
            return session.query(func.max(Alert.id)).scalar() or 0

    def statistics(self):
        with self.session_scope() as session:
            total = session.query(Alert).count()
            active = session.query(Alert).filter(Alert.blocked == False).count()
            types = dict(session.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).all())
        return {'total_alerts': total, 'active_threats': active, 'attack_types': types}

    def deactivate_flows(self, switch_id, match_fields=None):
        with self.session_scope() as session:
            query = session.query(FlowRule).filter(FlowRule.switch_id == str(switch_id))
            if match_fields is not None:
                query = query.filter(FlowRule.match_fields == match_fields)
            query.update({'active': False})

# Singleton instance
db = DatabaseManager()

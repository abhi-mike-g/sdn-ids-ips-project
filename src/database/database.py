from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager
from .models import Base, Alert, FlowRule, NetworkFlow, SystemMetrics
from ..utils.config import Config
import json

class DatabaseManager:
    def __init__(self):
        self.config = Config()
        self.engine = create_engine(
            self.config.get('database.url', 'sqlite:///nidps.db'),
            echo=False,
            pool_pre_ping=True
        )
        Base.metadata.create_all(self.engine)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
    
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
            session.close()
    
    def insert_alert(self, alert_data):
        """Insert a new alert"""
        with self.session_scope() as session:
            alert = Alert(**alert_data)
            session.add(alert)
            return alert.id
    
    def get_recent_alerts(self, limit=100, severity=None):
        """Get recent alerts"""
        with self.session_scope() as session:
            query = session.query(Alert).order_by(desc(Alert.timestamp))
            if severity:
                query = query.filter(Alert.severity <= severity)
            return query.limit(limit).all()
    
    def insert_flow_rule(self, rule_data):
        """Insert flow rule"""
        with self.session_scope() as session:
            rule = FlowRule(**rule_data)
            session.add(rule)
            return rule.id
    
    def get_active_flow_rules(self, switch_id=None):
        """Get active flow rules"""
        with self.session_scope() as session:
            query = session.query(FlowRule).filter(FlowRule.active == True)
            if switch_id:
                query = query.filter(FlowRule.switch_id == switch_id)
            return query.all()
    
    def insert_network_flow(self, flow_data):
        """Insert network flow record"""
        with self.session_scope() as session:
            flow = NetworkFlow(**flow_data)
            session.add(flow)
            return flow.id
    
    def insert_metrics(self, metrics_data):
        """Insert system metrics"""
        with self.session_scope() as session:
            metrics = SystemMetrics(**metrics_data)
            session.add(metrics)
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

# Singleton instance
db = DatabaseManager()

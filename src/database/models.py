from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(Integer)  # 1=Critical, 2=High, 3=Medium, 4=Low
    alert_type = Column(String(50), index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    signature = Column(String(255))
    description = Column(Text)
    raw_data = Column(Text)
    blocked = Column(Boolean, default=False)
    
class FlowRule(Base):
    __tablename__ = 'flow_rules'
    
    id = Column(Integer, primary_key=True)
    switch_id = Column(String(50), index=True)
    priority = Column(Integer)
    match_fields = Column(Text)  # JSON string
    actions = Column(Text)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    active = Column(Boolean, default=True)

class NetworkFlow(Base):
    __tablename__ = 'network_flows'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    duration = Column(Float)
    flags = Column(String(20))
    is_malicious = Column(Boolean, default=False)

class SystemMetrics(Base):
    __tablename__ = 'system_metrics'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    active_flows = Column(Integer)
    threats_detected = Column(Integer)
    throughput_mbps = Column(Float)
    latency_ms = Column(Float)

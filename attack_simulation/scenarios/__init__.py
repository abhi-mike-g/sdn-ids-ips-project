# attack_simulation/scenarios/__init__.py
ATTACK_SCENARIOS = {
    # Network Layer Attacks
    'port_scan': {
        'tool': 'nmap',
        'severity': 'medium',
        'detection': 'signature',
        'demo_time': '30s'
    },
    'syn_flood': {
        'tool': 'hping3',
        'severity': 'high',
        'detection': 'anomaly',
        'demo_time': '45s'
    },
    
    # Application Layer Attacks
    'sql_injection': {
        'tool': 'sqlmap',
        'severity': 'critical',
        'detection': 'signature',
        'demo_time': '60s'
    },
    'xss_attack': {
        'tool': 'burp_suite',
        'severity': 'high',
        'detection': 'signature',
        'demo_time': '45s'
    },
    
    # Authentication Attacks
    'brute_force': {
        'tool': 'hydra',
        'severity': 'high',
        'detection': 'anomaly',
        'demo_time': '60s'
    },
    
    # MITM Attacks
    'arp_spoofing': {
        'tool': 'ettercap',
        'severity': 'critical',
        'detection': 'both',
        'demo_time': '90s'
    },
    
    # IoT Specific
    'mqtt_injection': {
        'tool': 'mosquitto',
        'severity': 'medium',
        'detection': 'signature',
        'demo_time': '45s'
    }
}

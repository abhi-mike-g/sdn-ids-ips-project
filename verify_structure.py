#!/usr/bin/env python3
"""
Verify project structure and files
"""

import os
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

# Define required structure
REQUIRED_STRUCTURE = {
    'directories': [
        'src',
        'src/controller',
        'src/detection',
        'src/detection/rules',
        'src/network',
        'src/database',
        'src/dashboard',
        'src/dashboard/static',
        'src/dashboard/static/css',
        'src/dashboard/static/js',
        'src/dashboard/static/lib',
        'src/dashboard/templates',
        'src/attacks',
        'src/monitoring',
        'src/utils',
        'tests',
        'docs',
        'threat_model',
        'logs',
        'models',
        'config',
        'scripts'
    ],
    'files': {
        'root': [
            'README.md',
            'setup.sh',
            'requirements.txt',
            'verify_structure.py'
        ],
        'src': [
            '__init__.py'
        ],
        'src/controller': [
            '__init__.py',
            'sdn_controller.py',
            'flow_manager.py',
            'threat_detector.py',
            'policy_enforcer.py'
        ],
        'src/detection': [
            '__init__.py',
            'suricata_monitor.py',
            'traffic_analyzer.py',
            'ml_detector.py'
        ],
        'src/detection/rules': [
            'custom.rules'
        ],
        'src/network': [
            '__init__.py',
            'topology.py',
            'topology_manager.py',
            'network_monitor.py'
        ],
        'src/database': [
            '__init__.py',
            'models.py',
            'database.py',
            'schema.sql'
        ],
        'src/dashboard': [
            '__init__.py',
            'app.py',
            'api.py',
            'websocket.py'
        ],
        'src/dashboard/static/css': [
            'style.css'
        ],
        'src/dashboard/static/js': [
            'dashboard.js',
            'topology.js',
            'alerts.js',
            'metrics.js'
        ],
        'src/dashboard/templates': [
            'base.html',
            'dashboard.html',
            'topology.html',
            'logs.html',
            'metrics.html'
        ],
        'src/attacks': [
            '__init__.py',
            'attack_base.py',
            'attack_manager.py',
            'dos_attack.py',
            'port_scan.py',
            'mitm_attack.py',
            'sql_injection.py',
            'brute_force.py'
        ],
        'src/monitoring': [
            '__init__.py',
            'metrics_collector.py',
            'performance_monitor.py'
        ],
        'src/utils': [
            '__init__.py',
            'config.py',
            'logger.py'
        ],
        'tests': [
            '__init__.py',
            'test_controller.py',
            'test_detection.py',
            'test_attacks.py',
            'test_system.py'
        ],
        'docs': [
            'API_DOCS.md',
            'DEPLOYMENT.md',
            'ARCHITECTURE.md'
        ],
        'config': [
            'controller_config.json',
            'topology_config.json',
            'suricata.yaml'
        ],
        'threat_model': [
            'mitigation_mapping.json'
        ],
        'scripts': [
            'setup_environment.sh',
            'start_system.sh',
            'stop_system.sh',
            'run_demo.sh'
        ]
    }
}

def verify_structure():
    """Verify project structure"""
    
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Project Structure Verification")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    project_root = Path(__file__).parent
    issues = []
    
    # Check directories
    print(f"{Fore.YELLOW}Checking directories...")
    for dir_path in REQUIRED_STRUCTURE['directories']:
        full_path = project_root / dir_path
        if full_path.exists() and full_path.is_dir():
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {dir_path}")
        else:
            print(f"{Fore.RED}✗{Style.RESET_ALL} {dir_path}")
            issues.append(f"Missing directory: {dir_path}")
    
    # Check files
    print(f"\n{Fore.YELLOW}Checking files...")
    for location, files in REQUIRED_STRUCTURE['files'].items():
        if location == 'root':
            base_path = project_root
        else:
            base_path = project_root / location
        
        for file_name in files:
            full_path = base_path / file_name
            if full_path.exists() and full_path.is_file():
                print(f"{Fore.GREEN}✓{Style.RESET_ALL} {location}/{file_name}")
            else:
                print(f"{Fore.RED}✗{Style.RESET_ALL} {location}/{file_name}")
                issues.append(f"Missing file: {location}/{file_name}")
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}")
    if not issues:
        print(f"{Fore.GREEN}✓ All structure checks passed!")
    else:
        print(f"{Fore.RED}✗ Found {len(issues)} issues:")
        for issue in issues:
            print(f"  {Fore.RED}•{Style.RESET_ALL} {issue}")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    return len(issues) == 0

def check_imports():
    """Check if all modules can be imported"""
    
    print(f"{Fore.YELLOW}Checking imports...")
    
    modules_to_test = [
        'src.controller.sdn_controller',
        'src.detection.suricata_monitor',
        'src.database.database',
        'src.dashboard.app',
        'src.attacks.attack_manager',
        'src.monitoring.metrics_collector',
        'src.utils.config',
        'src.utils.logger'
    ]
    
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    
    import_issues = []
    
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {module_name}")
        except ImportError as e:
            print(f"{Fore.RED}✗{Style.RESET_ALL} {module_name}: {e}")
            import_issues.append(f"Import failed: {module_name}")
    
    return len(import_issues) == 0

if __name__ == '__main__':
    structure_ok = verify_structure()
    
    try:
        imports_ok = check_imports()
    except Exception as e:
        print(f"{Fore.YELLOW}⚠ Import check skipped: {e}")
        imports_ok = False
    
    if structure_ok and imports_ok:
        print(f"{Fore.GREEN}✓ Project structure is valid!")
        exit(0)
    elif structure_ok:
        print(f"{Fore.YELLOW}⚠ Structure OK but some imports failed")
        exit(1)
    else:
        print(f"{Fore.RED}✗ Project structure has issues")
        exit(1)

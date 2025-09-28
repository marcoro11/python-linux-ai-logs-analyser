import argparse
import hashlib
import json
import logging
import openai
import re
import sys
import yaml

from constants import LOG_PARSING_PATTERNS, SANITIZATION_PATTERNS, SYSTEM_PROMPT
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple


def sanitize_line(line: str, replacement_map: Dict[str, str]) -> str:
    sanitized = line
    for pattern_name, pattern in SANITIZATION_PATTERNS.items():
        matches = re.finditer(pattern, sanitized)
        for match in matches:
            sensitive_data = match.group(0)
            data_hash = hashlib.md5(sensitive_data.encode()).hexdigest()[:8]
            placeholder = f'[{pattern_name.upper()}_{data_hash}]'
            replacement_map[placeholder] = sensitive_data
            sanitized = sanitized.replace(sensitive_data, placeholder)
    return sanitized

def sanitize_logs(log_lines: List[str]) -> Tuple[List[str], Dict[str, str]]:
    replacement_map = {}
    sanitized_lines = [sanitize_line(line, replacement_map) for line in log_lines]
    return sanitized_lines, replacement_map

def detect_log_format(sample_lines: List[str]) -> str:
    format_scores = {fmt: 0 for fmt in LOG_PARSING_PATTERNS.keys()}
    for line in sample_lines[:10]:  # Test first 10 lines
        for fmt, pattern in LOG_PARSING_PATTERNS.items():
            if re.match(pattern, line.strip()):
                format_scores[fmt] += 1
    detected_format = max(format_scores, key=format_scores.get)
    return detected_format if format_scores[detected_format] > 0 else 'generic'

def parse_line(line: str, log_format: str) -> Dict[str, Any]:
    pattern = LOG_PARSING_PATTERNS.get(log_format, LOG_PARSING_PATTERNS['generic'])
    match = re.match(pattern, line.strip())
    if match:
        return match.groupdict()
    else:
        return {'raw_line': line, 'message': line}

def parse_logs(log_lines: List[str], log_format: Optional[str] = None) -> List[Dict[str, Any]]:
    if not log_format:
        log_format = detect_log_format(log_lines)
    parsed_logs = []
    for line in log_lines:
        if line.strip():
            parsed_log = parse_line(line, log_format)
            parsed_log['log_format'] = log_format
            parsed_logs.append(parsed_log)
    return parsed_logs

def analyze_logs(openai_config: Dict[str, Any], parsed_logs: List[Dict[str, Any]], log_level: str = 'all') -> Dict[str, Any]:
    api_key = openai_config.get('api_key')
    model = openai_config.get('model', 'gpt-4')
    base_url = openai_config.get('base_url', 'https://api.openai.com/v1')
    temperature = openai_config.get('temperature', 0.3)
    max_tokens = openai_config.get('max_tokens', 2000)
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    if log_level != 'all':
        filtered_logs = [log for log in parsed_logs 
                       if log.get('level', '').lower() == log_level.lower()]
    else:
        filtered_logs = parsed_logs
    if not filtered_logs:
        return {'error': f'No logs found for level: {log_level}'}
    log_summary = _prepare_log_summary(filtered_logs)
    user_prompt = f'''Please analyze these log entries:
Log Format: {filtered_logs[0].get("log_format", "unknown")}
Total Entries: {len(filtered_logs)}
Log Level Filter: {log_level}
{log_summary}
Provide your analysis in the requested JSON format.'''
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': user_prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens
        )
        content_raw = response.choices[0].message.content.strip()
        try:
            m = re.search(r"```json\s*(\{.*\})\s*```", content_raw, re.DOTALL)
            if m:
                content = m.group(1)
        except Exception as e:
            print(f'Error extracting JSON from response: {e}')
            sys.exit(1)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return {
                'summary': 'Analysis completed but response format was invalid',
                'raw_response': content,
                'error': 'Failed to parse AI response as JSON'
            }
    except Exception as e:
        return {'error': f'AI analysis failed: {str(e)}'}

def _prepare_log_summary(logs: List[Dict[str, Any]], max_entries: int = 50) -> str:
    summary_parts = []
    sample_logs = logs[:max_entries] if len(logs) > max_entries else logs
    for i, log in enumerate(sample_logs, 1):
        log_parts = []
        if 'timestamp' in log:
            log_parts.append(f'[{log["timestamp"]}]')
        if 'level' in log:
            log_parts.append(f'[{log["level"].upper()}]')
        if 'process' in log:
            log_parts.append(f'[{log["process"]}]')
        message = log.get('message', log.get('raw_line', ''))
        log_parts.append(message)
        summary_parts.append(f'{i}. {" ".join(log_parts)}')
    if len(logs) > max_entries:
        summary_parts.append(f'\n... and {len(logs) - max_entries} more entries')
    return '\n'.join(summary_parts)

def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('log_analyzer.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('log_analyzer')

def load_config(config_path: str, logger: logging.Logger) -> Dict[str, Any]:
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f'Config file not found: {config_path}')
        return {}
    except Exception as e:
        logger.error(f'Error loading config: {e}')
        return {}

def read_log_file(file_path: str, tail_lines: Optional[int], logger: logging.Logger) -> List[str]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        if tail_lines:
            lines = lines[-tail_lines:] if len(lines) > tail_lines else lines
        return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        logger.error(f'Error reading log file: {e}')
        return []

def print_results(results: Dict[str, Any]):
    print(f'AI LOG ANALYSIS RESULTS')
    if 'error' in results:
        print(f'Error: {results["error"]}')
        return
    if 'summary' in results:
        print(f'\nSUMMARY:')
        print(f'{results["summary"]}')
    if 'issues' in results:
        print(f'\nIDENTIFIED ISSUES:')
        for i, issue in enumerate(results['issues'], 1):
            severity = issue.get('severity', 'unknown').upper()
            print(f'[{severity}] {issue.get("description", "No description")}')
    if 'security_concerns' in results:
        print(f'\nSECURITY CONCERNS:')
        for concern in results['security_concerns']:
            print(concern)
    if 'recommendations' in results:
        print(f'\nRECOMMENDATIONS:')
        for i, rec in enumerate(results['recommendations'], 1):
            print(f'{i}. {rec}')
    if 'patterns' in results:
        print(f'\nOBSERVED PATTERNS:')
        for pattern in results['patterns']:
            print(f'{pattern}')

def run_analyzer(args):
    logger = setup_logging()
    config = load_config(args.config, logger)
    openai_config = config.get('openai', {})
    if args.api_key:
        openai_config['api_key'] = args.api_key
    if not openai_config.get('api_key'):
        print(f'Error: OpenAI API key required. Use --api-key or config file.')
        return 1
    print(f'Reading log file: {args.file}')
    log_lines = read_log_file(args.file, args.tail, logger)
    if not log_lines:
        print(f'No log lines found in file: {args.file}')
        return 1
    print(f'Found {len(log_lines)} log lines')
    if not args.no_sanitize:
        print(f'Sanitizing logs to remove sensitive data...')
        log_lines, _ = sanitize_logs(log_lines)
    print(f'Parsing logs...')
    parsed_logs = parse_logs(log_lines, args.format)
    detected_format = parsed_logs[0].get('log_format') if parsed_logs else 'unknown'
    print(f'Detected log format: {detected_format}')
    if args.ai_analyze:
        print(f'Analyzing logs with AI (model: {openai_config.get("model", "gpt-4")})...')
        results = analyze_logs(openai_config, parsed_logs, args.level)
    else:
        results = {'summary': 'Parsed logs', 'parsed_logs': parsed_logs}
    print_results(results)
    if args.output and 'error' not in results:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            print(f'Results saved to: {args.output}')
        except Exception as e:
            print(f'Error saving results to file: {e}')
    return 0

def main():
    parser = argparse.ArgumentParser(
        description='AI-powered Linux log analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -f /var/log/syslog --level error
  %(prog)s -f /var/log/apache2/error.log --format apache_error
  %(prog)s -f /var/log/auth.log --tail 100 --no-sanitize
  %(prog)s -f app.log --api-key sk-xxx --output analysis.json
        '''
    )
    parser.add_argument('-f', '--file', required=True, help='Log file to analyze')
    parser.add_argument('--level', default='all', 
                       choices=['all', 'debug', 'info', 'warning', 'error', 'critical'],
                       help='Log level to filter (default: all)')
    parser.add_argument('--format', 
                       choices=['syslog', 'apache_access', 'apache_error', 'nginx_access', 'nginx_error', 'auth', 'generic'],
                       help='Log format (auto-detected if not specified)')
    parser.add_argument('--tail', type=int, help='Analyze only last N lines')
    parser.add_argument('--api-key', help='OpenAI API key')
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--output', help='Output file for analysis results (JSON)')
    parser.add_argument('--no-sanitize', action='store_true', help='Skip sensitive data sanitization')
    parser.add_argument('--no-ai', dest='ai_analyze', action='store_false', default=True,
                       help='Skip AI analysis, just parse logs')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    if not Path(args.file).exists():
        print(f'Error: Log file not found: {args.file}')
        return 1
    return run_analyzer(args)

if __name__ == '__main__':
    sys.exit(main())
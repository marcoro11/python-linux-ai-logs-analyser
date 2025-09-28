# Linux Log Analyzer - Find Issues with AI

This tool helps you quickly identify problems, security concerns, and performance bottlenecks in your Linux server logs using the power of AI.  It automatically protects your privacy by scrubbing sensitive data before sending anything to the AI.

---

## What it Does

This analyzer takes your Linux logs (like syslog, Apache access logs, etc.) and uses AI to:

*   **Spot Anomalies:**  Find unusual events that might indicate a problem.
*   **Identify Security Issues:** Detect suspicious logins, failed authentication attempts, and other security threats.
*   **Pinpoint Performance Bottlenecks:**  Find slow queries, resource exhaustion, and other performance problems.

---

## Getting Started

Here's how to get up and running quickly:

### Prerequisites

*   Python 3.12 or higher
*   Pipenv
*   An OpenAI API key

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/marcoro11/python-linux-ai-logs-analyser.git
    cd python-linux-ai-logs-analyser
    ```

2.  **Install dependencies:**
    ```bash
    pip install --user pipenv
    pipenv install
    ```

3.  **Set your OpenAI API key:**
    *   Edit the `config/config.yaml` file directly and paste your key there.

4.  **Run your first analysis:**
    ```bash
    pipenv run python main.py -f /var/log/syslog
    ```

---
## Usage Examples

### Basic Analysis

```bash
pipenv run python main.py -f /var/log/syslog  # Analyze the system log
pipenv run python main.py -f examples/sample_logs/auth.log # Analyze a sample auth log
```

### Advanced Options
```bash
pipenv run python main.py -f /var/log/auth.log --output results.json # Save the output to a JSON file
pipenv run python main.py -f /var/log/nginx/access.log --config custom-config.yaml # Use a different configuration file
pipenv run python main.py -f /var/log/syslog --verbose # Get more detailed output
```

### Batch Analysis
```bash
pipenv run python main.py -f examples/sample_logs/*.log # Analyze all log files in the sample directory
```
---

## Configuration (config/config.yaml)
The tool uses config/config.yaml for its settings.  You can customize:

- API Keys: Your OpenAI API key (required).
- Parsing: How the tool identifies log formats. It can usually auto-detect, but you can specify supported formats if needed.
- Sanitization: How sensitive data is protected before sending it to the AI (see "Data Sanitization" below).
- Output: How the results are displayed or saved.

Here's an example config/config.yaml:

```yaml
openai:
  api_key: ""
  model: "gpt-4.1"
  max_tokens: 500
  temperature: 0.3

parsing:
  auto_detect: true
  supported_formats: ["syslog", "apache", "nginx", "auth", "generic"]

sanitization:
  hash_algorithm: "sha256"
  patterns:
    - ip_address
    - email
    - username
    - uuid
    - mac_address

output:
  format: "console"
  color: true
  save_json: false
  json_path: "analysis_report.json"

logging:
  level: "INFO"
  file: "analyzer.log"
```

---

## Analysis Categories

- **Security**: Detects suspicious logins, privilege escalations, and failed authentications.
- **Performance**: Identifies slow queries, resource bottlenecks, and system warnings.
- **Anomaly**: Flags unusual patterns or spikes in activity.
- **Info**: Summarizes normal operations and noteworthy events.

---

## Data Sanitization: Protecting Your Privacy

Sensitive data (IP addresses, email addresses, usernames, UUIDs, MAC addresses) is automatically hashed before being sent to the AI model. You can customize or extend these patterns in config.yaml. This helps protect your privacy and ensures that no personally identifiable information is shared with the model.

### Nice-to-Have:
- Integrate a local model to keep the logs private.
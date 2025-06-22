# SigmaDFT

Digital Forensics Timeline Analysis using Sigma-like rules for event reconstruction.

## Description

SigmaDFT is a Python package that analyzes digital forensics timelines using YAML-based detection rules. It processes CSV files from forensics tools like Plaso and applies custom rules to identify suspicious activities and reconstruct high-level events.

## Features

- **Timeline Analysis**: Process CSV timeline files from forensics tools
- **YAML Rules**: Use Sigma-like YAML rules for event detection  
- **Event Reconstruction**: Convert low-level events to meaningful high-level events
- **Multiple Rule Types**: Support for web activity, authentication, system changes, and security events
- **JSON Output**: Export results in structured JSON format
- **Flexible Matching**: Support regex and keyword-based event matching

## Prerequisites

- Anaconda or Miniconda
- Git

## Installation

### 1. Create and Activate Environment

```bash
# Create a new conda environment
conda create --name sigmadft python=3.12

# Activate the environment
conda activate sigmadft
```

### 2. Install SigmaDFT

```bash
# Clone the repository
git clone https://github.com/yourusername/sigmadft.git
cd sigmadft

# Install the package
pip install .

# For development (editable install)
pip install -e .
```

### 3. Verify Installation

```bash
# Check if package is installed
pip list | grep sigmadft

# Test the command
sigmadft -h
```

## Usage

### Basic Commands

```bash
# Basic timeline analysis
sigmadft -i timeline.csv -o results.json

# Analyze specific event types
sigmadft -i timeline.csv -o results.json -t google-search
sigmadft -i timeline.csv -o results.json -t all-web-activity
sigmadft -i timeline.csv -o results.json -t authentication-activity

```

### Available Event Types

| Type | Description |
|------|-------------|
| `google-search` | Google search activities |
| `bing-search` | Bing search activities |
| `web-visits` | General web browsing |
| `youtube-watch` | YouTube viewing activities |
| `all-web-activity` | All web-related activities |
| `user-add` | User account creation |
| `user-mod` | User account modifications |
| `account-management-activity` | All user management activities |
| `auth-failure` | Authentication failures |
| `session-opened` | Session login events |
| `authentication-activity` | All authentication events |
| `web-shell` | Web shell detection |
| `security-tools` | Security tools disabling syslog |
| `suspicious-dns` | Suspicious DNS activities |
| `crontab-modification` | Crontab file modifications |
| `ftp-errors` | VSFTPD suspicious error messages |
| `suspicious-logs` | Suspicious shell log entries |
| `all-linux-security` | All Linux security events |
| `all` | All available rules |


### Example Analysis

```bash
# Analyze web browsing activity
sigmadft -i plaso_timeline.csv -o web_analysis.json -t all-web-activity

# Detect authentication issues
sigmadft -i auth_logs.csv -o auth_analysis.json -t authentication-activity

# Comprehensive security analysis
sigmadft -i full_timeline.csv -o security_analysis.json -t all-linux-security
```

## Input Format

SigmaDFT expects CSV files in Plaso format with the following columns:

- `datetime`: Timestamp of the event
- `timestamp_desc`: Description of the timestamp
- `source`: Event source
- `source_long`: Detailed source information
- `message`: Event message/evidence
- `parser`: Parser used to extract the event
- `display_name`: Display name/path
- `tag`: Event tags

## Output Format

Results are exported in JSON format containing:

- Event metadata (timestamps, sources, etc.)
- Reconstructed high-level events
- Supporting evidence
- Rule match information
- Event categorization

## Rule Development

### Rule Structure

Rules are defined in YAML format similar to Sigma rules:

```yaml
title: "Example Detection Rule"
id: "example-001"
description: "Detects example activities"
category: "example"
detection:
  keywords:
    - "example_keyword"
    - "another_keyword"
  condition: "keywords"
high_level_event:
  type: "Example Activity"
  description: "User performed {example_key}"
  keys:
    - name: "example_key"
      source: "extract_example_data"
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the [pyDFT](https://bitbucket.org/chrishargreaves/pydft-analysers) project
- Uses Sigma-like rule format for digital forensics
- Built for the digital forensics and incident response community

## Support

- Create an issue for bug reports or feature requests
- Check existing issues before creating new ones
- Provide sample data and steps to reproduce for bug reports

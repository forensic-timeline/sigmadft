# SigmaDFT

Digital Forensics Timeline Analysis using Sigma-like rules for event reconstruction.

## Description

SigmaDFT is a Python package that analyzes digital forensics timelines using YAML-based detection rules. It processes CSV files from forensics tools like Plaso and applies custom rules to identify suspicious activities and reconstruct high-level events.

## Features

- **Timeline Analysis**: Process CSV timeline files from forensics tools
- **YAML Rules**: Use Sigma-like YAML rules for event detection  
- **Multiple Rule Sources**: Choose between [Atlas](https://github.com/forensic-timeline/atlas) rules and [SigmaHQ](https://github.com/SigmaHQ/sigma) rules (or both) through pluggable rule adapters
- **Event Reconstruction**: Convert low-level events to meaningful high-level events
- **Multiple Rule Types**: Support for web activity, authentication, system changes, and security events
- **JSON / CSV Output**: Export results in structured JSON or CSV format
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

### Command-Line Options

| Option | Required | Description |
|--------|----------|-------------|
| `-i`, `--input_path` | Yes | Path to a Plaso CSV timeline. |
| `-o`, `--output_path` | Yes | Output file. The format follows the extension: `.json` or `.csv`. |
| `-s`, `--rule-source` | No | Rule source: `atlas` (default), `sigma`, or `all` (both). See [Rule Sources](#rule-sources). |

### Basic Commands

```bash
# Basic timeline analysis with Atlas rules (default, JSON output)
sigmadft -i timeline.csv -o results.json

# CSV output (format follows the -o extension: .json or .csv)
sigmadft -i timeline.csv -o results.csv

# Choose the rule source
sigmadft -i timeline.csv -o atlas_results.csv -s atlas   # Atlas rules (default)
sigmadft -i timeline.csv -o sigma_results.csv -s sigma   # SigmaHQ rules
sigmadft -i timeline.csv -o all_results.csv   -s all     # Atlas + SigmaHQ rules
```

### Rule Sources

Rules live in `src/sigmadft/rules/`, one folder per source. Each source has a
rule adapter (`src/sigmadft/adapters/`) that converts its rule format into the
internal SigmaDFT rule model, so the rest of the pipeline is the same for every
source.

| Source (`-s`) | Folder | Format | Output event |
|---------------|--------|--------|--------------|
| `atlas` (default) | `rules/atlas/rules/` | Native SigmaDFT format: `detection.keywords` (modifiers `re`, `all`) plus `high_level_event` (type, description template, extracted keys). | `type`, `description` and `keys` from `high_level_event`. |
| `sigma` | `rules/sigma/` | Standard [Sigma](https://github.com/SigmaHQ/sigma-specification) rules, parsed with [pySigma](https://github.com/SigmaHQ/pySigma): field selections, modifiers (`contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `cased`, ...) and conditions (`and`, `or`, `not`, `1 of`, `all of`). | `type` = rule `title`, `description` = rule `description`, `category` = `logsource` category/service/product, no `keys`. |
| `all` | both | Atlas and Sigma rules in a single run. | Both of the above, merged into one timeline. |

**How Sigma rules are matched (loose field mapping).** A Plaso CSV row has no
structured fields (`Image`, `CommandLine`, `c-useragent`, ...), so field names
are ignored and every value is searched in the row text
`"{timestamp_desc}-{source} {message} {source}-{source_long}-{parser}"`:

- Matching is case-insensitive, as in Sigma (unless `|cased`).
- Keywords (values without a field) are plain substring searches.
- Exact values and `startswith` / `endswith` may appear anywhere in the row, but
  the anchored side must sit on a token boundary (not next to `[A-Za-z0-9_-]`).
- `field: ''` and `field: null` cannot be checked from free text and never match.
- `?` and `*` are Sigma wildcards; escape them (`\?`, `\*`) to match the literal character.

Loose mapping lets every Sigma rule run on a Plaso timeline, but it can give
false positives (e.g. user-agent rules that expect an exact value). Many Sigma
rules (e.g. `process_creation`) also need log sources that a Plaso timeline
usually does not contain.

To add another rule source, create an adapter that subclasses
`sigmadft.adapters.base.RuleAdapter` (set `name`, `rules_subdir`, implement
`load()`) and register it in `ADAPTERS` in `sigmadft/adapters/__init__.py`; it
then becomes available as a `-s` choice.

### Example Analysis

```bash
# Reconstruct events from a Plaso timeline with Atlas rules
sigmadft -i plaso_timeline.csv -o plaso_timeline.json

# Compare Atlas and SigmaHQ rules on the same timeline
sigmadft -i plaso_timeline.csv -o atlas_plaso_timeline.csv -s atlas
sigmadft -i plaso_timeline.csv -o sigma_plaso_timeline.csv -s sigma

# Run every available rule (Atlas + SigmaHQ) at once
sigmadft -i plaso_timeline.csv -o all_plaso_timeline.json -s all
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

The output format follows the extension of `-o`:

- `.json`: a dictionary keyed `"0"`, `"1"`, ... with one high-level event per entry.
- `.csv`: one row per high-level event; `keys` is stored as a JSON string.

Each high-level event has the following fields:

| Field | Description |
|-------|-------------|
| `id` | Line number of the matching row in the input CSV |
| `date_time_min`, `date_time_max` | Event timestamp (range) |
| `evidence_message` | `message` of the matching row |
| `type` | Event type (Atlas: `high_level_event.type`; Sigma: rule `title`) |
| `description` | Event description (Atlas: filled template; Sigma: rule `description`) |
| `category` | Rule category (Sigma: `logsource` category/service/product) |
| `plugin` | `{source}-{source_long}-{parser}` of the matching row |
| `files` | `display_name` of the matching row |
| `keys` | Values extracted by the Atlas rule's key functions (empty for Sigma rules) |

If no rule matches, no output file is written.

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

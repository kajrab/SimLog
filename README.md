# SimLog

A not fancy log analyzer that parses auth.log and flags suspicious IPs. 

---

## Features

- Detects brute force attempts by failed login count
- Flags successful logins after failures 
- Configurable threshold

---

## Install

```bash
git clone https://github.com/kajrab/simlog
cd simlog
```

---

## Usage

```bash
python main.py --log /var/log/auth.log
```

> **Disclaimer:** I haven't tested this project on a real server yet, so it may not work as expected.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--log` | required | Path to log file |
| `--threshold` | `5` | Failed attempts before flagging |
| `--output` | none | Save results to file |

### Examples

```bash
# Basic scan
python main.py --log /var/log/auth.log

# Custom threshold
python main.py --log /var/log/auth.log --threshold 3

# Save results
python main.py --log /var/log/auth.log --output results.txt

# Full options
python main.py --log /var/log/auth.log --threshold 3 --output results.txt
```

---

## Output

```
[COMPROMISE]   192.168.1.105 — 10 failed attempts | successful login after failures
[SUSPICIOUS]   10.0.0.22     — 6 failed attempts
[CLEAN] No suspicious activity detected.
```

---

## Project Structure

```
simlog/
  main.py        # CLI, parsing, analysis, report
  data/
    sample.log   # Sample log for testing
  requirements.txt
  README.md
  LICENSE
  .gitignore
```

---

## Testing

A sample log is included in `data/sample.log` to test immediately without a live server:

```bash
python main.py --log data/sample.log
```

---

## Disclaimer

This is a personal project built for practicing Python scripting and comes with no guarantee in real-world cases. Treat this repo as an experiment or a study. SimLog is designed to help identify suspicious activity in system logs. Only use it against systems you own or have explicit permission to monitor.

---

## License

MIT

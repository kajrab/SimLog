import argparse


def parse_log(filepath):
    log = {}
    with open(filepath) as f:
        for line in f:
            date = line[:15]
            line = line[35:]
            split = line.split("from")
            if len(split) < 2:
                continue
            ip = split[1].split("port")[0].strip()
            event = split[0].rstrip(" ")
            if ip not in log:
                log[ip] = []
            log[ip].append({"event": event, "date": date})
    return log


def analyze(log, threshold=5):
    results = []
    for ip, events in log.items():
        failed = sum(
            1 for e in events if "Failed" in e["event"] or "Invalid" in e["event"]
        )
        had_failure = failed > 0
        compromised = any("Accepted" in e["event"] for e in events) and had_failure

        if failed >= threshold or compromised:
            severity = "COMPROMISE" if compromised else "SUSPICIOUS"
            reasons = []
            if failed >= threshold:
                reasons.append(f"{failed} failed attempts")
            if compromised:
                reasons.append("successful login after failures")
            results.append({"ip": ip, "severity": severity, "reasons": reasons})

    return results


def report(results, output=None):
    if not results:
        print("[CLEAN] No suspicious activity detected.")
        return
    lines = []
    for r in results:
        tag = f"[{r['severity']}]".ljust(14)
        line = f"{tag} {r['ip']} — {' | '.join(r['reasons'])}"
        print(line)
        lines.append(line)

    if output:
        with open(output, "w") as f:
            f.write("\n".join(lines))
        print(f"\n[+] Results saved to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SimLog — Simplified Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts before flagging (default 5)",
    )
    parser.add_argument("--output", help="Save results to file")
    args = parser.parse_args()

    log = parse_log(args.log)
    results = analyze(log, args.threshold)
    report(results, args.output)

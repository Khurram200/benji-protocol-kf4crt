# The Benji Protocol — Build Log

**Student Name:** Khurram Farooqui
**Student ID:** kf4crt
**GitHub Repository:** [https://github.com/Khurram200/benji-protocol-kf4crt](https://github.com/Khurram200/benji-protocol-kf4crt)

---

> "Benji documents everything. Not because he is asked to. Because a tool with
> no history is a tool you cannot trust, and a mission with no record is a
> mission that never happened."

This is your running build log. Update it after every significant coding
session. It is not an essay — it is a technical journal. Short entries are
fine. No entry is not fine.

The build log serves three purposes:

1. It is evidence of your development process for the portfolio marker.
2. It is your own reference when something breaks at 23:00 the night before
  the Vulnerability Hunt.
3. It demonstrates that the code in your repository is yours.

---

## How to Use This Document

Add a new entry for each session using the template below. Commit this file
alongside your code — the build log and the code should tell the same story.

---

## Entry Template

### [DATE] — [TASK / SESSION]

**What I built / changed:**

**What broke and how I fixed it:**

**Decisions I made and why:**

**What the tool output when I ran it against Metasploitable:**

**Questions or things to revisit:**

---

## Week 1 — Task 1: Evidence Collector

### [24/04/2026] — Session A

**What I built / changed:**

- Prepared and validated `toolkit/task1_evidence_collector/log_parser.py` workflow using assignment-style auth log input.
- Confirmed output target file handling for `suspects.csv`.

**What broke and how I fixed it:**

- Initial parser run against SSH debug-style log content returned header-only CSV.
- Replaced test input with auth-log style entries (`Failed password` / `Invalid user`) aligned to parser contract.

**Decisions I made and why:**

- Kept parser invocation command-line based (`argparse`) for field-test compatibility.
- Used evidence format that matches required extraction fields: timestamp, IP, username.

**What the tool output when I ran it against Metasploitable:**

- Command used:
`python3 toolkit/task1_evidence_collector/log_parser.py Auth.log`
- Output file generated:
`toolkit/task1_evidence_collector/suspects.csv`
- Result observed:
`Timestamp,IP_Address,User_Account` (header present; row count depends on matching log patterns).

**Questions or things to revisit:**

- Re-check parser regex against all variant auth-log formats before final submission.

### [24/04/2026] — Session B

**What I built / changed:**

- Updated Task 1 evidence input file content to reflect realistic brute-force/authentication traces.
- Re-ran parser to verify output generation path and formatting.

**What broke and how I fixed it:**

- No runtime crash; issue was data-format mismatch rather than code failure.

**Decisions I made and why:**

- Preserved CSV header format exactly as required by the field-test contract.

**What the tool output when I ran it against Metasploitable:**

- Parser executed successfully and produced `suspects.csv` without exceptions.

**Questions or things to revisit:**

- Add additional fixture checks for deduplication behavior if duplicate failed-auth lines appear.

---

## Week 2 — Task 2: Network Cartographer

### [24/04/2026] — Session A

**Metasploitable scan output (paste key results):**

```json
{
  "target": "172.16.19.200",
  "open_ports": [
    {"port": 21, "banner": "220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [172.16.19.200]"},
    {"port": 22, "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"},
    {"port": 80, "banner": "HTTP/1.1 400 Bad Request ... Server: Apache/2.4.7 (Ubuntu)"},
    {"port": 445, "banner": ""},
    {"port": 631, "banner": ""},
    {"port": 3306, "banner": "Host '172.16.19.10' is not allowed to connect to this MySQL server"},
    {"port": 3500, "banner": "HTTP/1.1 400 Bad Request ... WEBrick/1.3.1 (Ruby/2.3.8)"},
    {"port": 6697, "banner": ":irc.TestIRC.net NOTICE AUTH ..."},
    {"port": 8080, "banner": ""}
  ]
}
```

**Observations — what services did you find? What do the banners tell you?**

- Multiple externally reachable services identified (FTP, SSH, HTTP, MySQL-related, IRC, additional web service).
- Banner intelligence confirms likely Linux stack and old service versions useful for prioritizing attack path.
- Web and SSH evidence gave the best operational route into Mission Phase 1 -> Phase 2 progression.

### [24/04/2026] — Session B

**What I built / changed:**

- Persisted recon output to `toolkit/task2_network_cartographer/recon_results.json`.

**What broke and how I fixed it:**

- No scan-logic blocker during this session; focus was evidence quality and report integration.

**Decisions I made and why:**

- Captured key banners exactly (not paraphrased) to maximize evidence value in `REPORT.md`.

**What the tool output when I ran it against Metasploitable:**

- Confirmed open ports: `21, 22, 80, 445, 631, 3306, 3500, 6697, 8080`.

**Questions or things to revisit:**

- Validate timeout/thread balance before final timed run for consistent completion speed.

---

## Week 3 — Task 3: Access Validator

### [24/04/2026] — Session A

**What I built / changed:**

- Prepared task wordlist and executed SSH credential validation workflow against target user from recon.

**What broke and how I fixed it:**

- No tool crash; ensured wordlist path and username matched enum output exactly (`s.lane`).

**Decisions I made and why:**

- Used command-line run that mirrors assignment sequence and generates strong evidence trail.

**What the tool output when I ran it against Metasploitable:**

- Command:
`python toolkit/task3_access_validator/brute.py 172.16.19.200 --service ssh --user s.lane --wordlist toolkit/task3_access_validator/wordlist.txt`
- Output highlights:
  - `[*] Loaded 228 passwords ...`
  - `[+] SUCCESS: Password found: fluffybunny`
  - `[*] Valid credentials found: s.lane:fluffybunny`

**Questions or things to revisit:**

- Keep attempt logging file archived as supporting operational evidence.

### [24/04/2026] — Session B

**What I built / changed:**

- Performed direct SSH verification for discovered credentials.

**What broke and how I fixed it:**

- Initial SSH connection halted at host-key verification prompt (`Host key verification failed`).
- Accepted fingerprint and retried successfully.

**Decisions I made and why:**

- Captured full `ssh -v` evidence to validate real authenticated access beyond brute-tool success output.

**What the tool output when I ran it against Metasploitable:**

- `Authenticated to 172.16.19.200 ([172.16.19.200]:22) using "password".`
- `Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)`

**Questions or things to revisit:**

- Ensure host-key handling is documented clearly in final report narrative.

---

## Week 4 — Task 4: Web Enumerator

### [24/04/2026] — Session A

**Metasploitable web recon output:**

- Command:
`python3 toolkit/task4_web_enumerator/web_enum.py http://172.16.19.200`
- Header finding:
`Server: Apache/2.4.7 (Ubuntu)`

**HTML comments found:**

- `dev: s.lane - temp access pending IT ticket #4471 - remove before live`
- `staging DB config moved to /dbadmin - credentials as per onboarding doc`

**Sensitive paths found:**

- `/robots.txt — NOT FOUND (404)`
- `/admin — NOT FOUND (404)`
- `/phpmyadmin — FORBIDDEN (403)`
- `/login — NOT FOUND (404)`
- `/.git — NOT FOUND (404)`

### [24/04/2026] — Session B

**What I built / changed:**

- Integrated web recon evidence into Phase 1 diagnostic narrative.

**What broke and how I fixed it:**

- No runtime blocker in this phase; primary task was evidence accuracy and completeness.

**Decisions I made and why:**

- Treated HTML comments as high-value information disclosure indicators driving username/path selection.

**What the tool output when I ran it against Metasploitable:**

- Comment and path probe outputs directly informed credential-acquisition strategy.

**Questions or things to revisit:**

- Include screenshot evidence references for enum output in final report consistency check.

---

## Week 5 — Vulnerability Hunt

> This section is your mission log. Update it in real time during the session.
> Benji does not write the mission log after the mission. He writes it during.

### Pre-Hunt Checklist

- All four toolkit tools pass their field tests locally
- `requirements.txt` is up to date (`pip freeze > requirements.txt`)
- `AI_LOG.md` is current
- `vulnerability_hunt/exploit.py` — argument parsing in place
- `vulnerability_hunt/fix.py` — argument parsing in place
- `vulnerability_hunt/REPORT.md` — headings populated, ready to fill
- Git remote confirmed, can push
- Tags w1, w2, w3, w4 in place

### Hunt Log

**[TIME] — Diagnosis phase:**

- Ran network reconnaissance and confirmed multi-service exposure on `172.16.19.200`.
- Key open ports observed: `21, 22, 80, 445, 631, 3306, 3500, 6697, 8080`.
- Service/banner highlights recorded in `REPORT.md` Section 1.
- Executed web enumeration command:
`python3 toolkit/task4_web_enumerator/web_enum.py http://172.16.19.200`

**[TIME] — Vulnerability identified:**

- Information disclosure found in web comments from `web_enum.py`.
- Leaked username clue: `s.lane`.
- Additional clue: `staging DB config moved to /dbadmin - credentials as per onboarding doc`.

**[TIME] — Exploit development:**

- Ran credential validation:
`python toolkit/task3_access_validator/brute.py 172.16.19.200 --service ssh --user s.lane --wordlist toolkit/task3_access_validator/wordlist.txt`
- Tool loaded `228` candidate passwords and attempted SSH authentication sequentially.
- Successful credential discovered at attempt `164/228`.
- Success evidence:
  - `[+] SUCCESS: Password found: fluffybunny`
  - `[*] Valid credentials found: s.lane:fluffybunny`
- Next step: use recovered SSH credentials to locate evidence log and extract mission flag.
- Updated local evidence file `toolkit/task1_evidence_collector/Auth.log` to support Task 1 parser input/testing workflow.
- Ran SSH validation command: `ssh -v s.lane@172.16.19.200`.
- First attempt failed at host-key prompt (`Host key verification failed`), then accepted fingerprint and retried.
- Confirmed authenticated shell access with:
  - `Authenticated to 172.16.19.200 ... using "password"`
  - `Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)`
- Ran parser command for evidence extraction:
`python3 toolkit/task1_evidence_collector/log_parser.py Auth.log`
- Captured resulting CSV at:
`toolkit/task1_evidence_collector/suspects.csv`

**[TIME] — Flag retrieved:**

```
FLAG:
```

**[TIME] — Remediation:**

**[TIME] — Final commit and push:**
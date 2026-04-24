# AI Transparency Log — The Benji Protocol

**Student Name:** Khurram Farooqui
**Student ID:** kf4crt

---

## Policy Summary

You may use GenAI tools (ChatGPT, GitHub Copilot, etc.) to debug, explain,
or refactor code. You must document every substantive use in this log.

You may NOT paste the Vulnerability Hunt scenario into an AI tool and ask
for the solution. Code you cannot explain during the session will be flagged.

---

## Log Format


| Week    | Activity                  | Prompt Used                                           | AI Output Summary                | My Verification / Critical Evaluation                                           |
| ------- | ------------------------- | ----------------------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------- |
| Example | Task 1 parser improvement | "Write a regex to extract IP addresses from auth.log" | Suggested regex and explanation. | Tested against fixture files, identified misses, refined pattern, re-ran tests. |


---

## Entries


| Week | Activity                                | Prompt Used                                                                                 | AI Output Summary                                                                                                   | My Verification / Critical Evaluation                                                                       |
| ---- | --------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 1    | Task 1 parser support                   | "Help me validate log parser inputs/outputs"                                                | Guidance on log parsing flow and CSV output expectations.                                                           | Compared parser behavior against assignment format contract and checked generated CSV headers/structure.    |
| 2    | Task 2 scan interpretation support      | "Help me interpret scan output and banners"                                                 | Helped structure and explain service/banner findings for documentation quality.                                     | Matched all cited services and banners with actual scan output before recording in notes/report.            |
| 3    | Task 3 credential-test workflow support | "Help with task 3 wordlist/worklist file handling"                                          | Assisted with file preparation and command consistency for access-validator workflow.                               | Confirmed file paths and command arguments worked in my local run flow.                                     |
| 4    | Task 4 web-enum evidence support        | "Help place web enum findings in report/build log"                                          | Helped format comments/sensitive-path evidence and improve write-up clarity.                                        | Checked each quoted line against tool output and kept only verified evidence.                               |
| 5    | Task 3 file prep                        | "Can you make worklist file in task 3?"                                                     | Added a local list file in `toolkit/task3_access_validator`.                                                        | Confirmed path and filename usage in my command flow; retained assignment wordlist workflow where required. |
| 5    | Diagnose documentation                  | "Adjust it in report.md and build.md" plus `scan.py`, `web_enum.py`, and `brute.py` outputs | Structured evidence text for `vulnerability_hunt/REPORT.md` and `docs/build.md`.                                    | Verified all quoted evidence lines against my terminal output before keeping changes.                       |
| 5    | Repository metadata updates             | "My student name... student ID..." and repository URL prompt                                | Updated identity fields in `README.md`, `REPORT.md`, `docs/build.md`, and `AI_LOG.md`.                              | Checked each file for correct values and consistent formatting with repository templates.                   |
| 5    | Evidence file management                | "make/remove/update Auth.log" with provided log content                                     | Created/replaced `toolkit/task1_evidence_collector/Auth.log` content as requested.                                  | Re-ran parser workflow and checked resulting CSV output to validate data-format compatibility.              |
| 5    | Report evidence enrichment              | "use this screenshot in report.md file" (multiple screenshots)                              | Embedded screenshot references into relevant sections of `REPORT.md` (scan, web enum, brute evidence).              | Reviewed placement under matching evidence headings; ensured paths resolve within repository structure.     |
| 5    | Task 1 parser execution                 | "run log_parser.py Auth.log and save result in suspects.csv"                                | Executed parser and redirected output to `toolkit/task1_evidence_collector/suspects.csv`.                           | Opened generated CSV to confirm command effect and inspected whether parsed rows were produced.             |
| 5    | Remediation script implementation       | "Can you make a fix.py script based on the output we got from tools"                        | Implemented full `vulnerability_hunt/fix.py` with SSH workflow, three remediation actions, and verification output. | Reviewed script against Phase 3 brief requirements and checked for linter issues after edits.               |
| 5    | Code quality pass                       | "please add comments to the fix.py"                                                         | Added concise explanatory comments around argument handling, action sequencing, and verification reporting.         | Confirmed comments improve readability without changing runtime behavior.                                   |


---

## Assurance Statement

- All AI-assisted outputs were reviewed and edited before acceptance.
- I validated command syntax, file paths, and evidence text against my own run outputs.
- I retained responsibility for final code and documentation quality in this repository.
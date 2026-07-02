# Community templates

Templates in this directory are auto-registered at startup by the scanner
template registry (see `directoryTemplates()` in `../../templates.go`) — drop a
Nuclei-format `.yaml` file here and it becomes an available test type
(`COMMUNITY_<ID>`) with no Go code change. They run self-contained against the
target `{{BaseURL}}` and do not use Karaxys's crafted-request template variables
(`{{polluted_body}}`, `{{attack_token}}`, etc.).

## Provenance / expanding this set

These are hand-picked, generic, low-false-positive checks. To expand coverage
from the upstream Nuclei community library
(https://github.com/projectdiscovery/nuclei-templates):

1. Pull from a **pinned commit/tag**, not `main`, so template changes are a
   reviewed action rather than silent drift. Record the commit here when you do.
2. Curate by tag — `exposures`, `misconfiguration`, `default-logins`,
   `takeovers`, and API-relevant `cve` entries — rather than importing wholesale.
   Most of the upstream repo targets general web apps and is noise for an API
   scanner.
3. **Exclude `code:`-protocol templates.** Nuclei's `code:` type executes
   arbitrary local commands and is an RCE surface if a bad template slips in.
   Only `http:`-protocol templates belong here.
4. Re-run `make test-fast` after adding templates — the registry validates that
   every template parses and has the required metadata at load time.

## Result convention

A community template needs no special matcher naming. The worker treats any
matched Nuclei matcher as a finding (`MatcherStatus == true`), except matchers
explicitly named `secure` or `error` (reserved sentinels used by Karaxys's
hand-authored templates for non-findings). Standard upstream templates that emit
a result only on a positive match therefore work unmodified.

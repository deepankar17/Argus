"""LLM and MCP static checks.

- Hidden characters (zero-width, bidi controls, Unicode tag characters) in code and in the text
  files AI agents read (CLAUDE.md, AGENTS.md, skills, prompts, tool descriptions). They hide
  instructions from human reviewers ("Trojan Source", ASCII smuggling).
- Prompt-injection phrasing in those agent-read files and in MCP tool descriptions in source.
- MCP client configs committed with a token in them.
"""
import json
import re

from ..core import Finding, git_files, line_of

NAME = "llm-static"
CATEGORY = "LLM / MCP"

# Deliberately NOT including U+200C/U+200D (ZWNJ/ZWJ): they are legitimate joiners in Indic scripts
# and emoji sequences, so flagging them buries real findings under localized-string noise.
HIDDEN = re.compile("[​⁠-⁤‪-‮⁦-⁩﻿\U000e0000-\U000e007f]")
BIDI = re.compile("[‪-‮⁦-⁩]")
TAGS = re.compile("[\U000e0000-\U000e007f]")
# Localized string resources, where zero-width formatting characters are expected.
LOCALE = re.compile(r"values(-[\w+-]+)?/|/l10n/|\.arb$|(^|/)strings[\w.]*\.xml$|/res/.*/strings", re.I)
AGENT_FILES = re.compile(r"(^|/)(CLAUDE|AGENTS|GEMINI|COPILOT|\.cursorrules|\.windsurfrules|SKILL)(\.md)?$|"
                         r"(^|/)(\.claude|\.cursor|\.github/copilot|prompts?|skills?|agents?)/.*\.(md|txt|json|ya?ml)$|"
                         r"\.prompt(\.md)?$", re.I)
INJECTION = [
    (r"ignore (all |any )?(previous|prior|above) (instructions|prompts)", "tells the model to ignore its instructions"),
    (r"(do not|don't|never) (tell|inform|mention|reveal)[^.\n]{0,40}(user|owner|human)", "hides actions from the user"),
    (r"<\s*(important|system|secret)\s*>", "fake system or <IMPORTANT> tag"),
    (r"(read|cat|send|upload|exfiltrate)[^.\n]{0,40}(~/\.ssh|id_rsa|\.aws/credentials|\.env\b|keychain)", "reaches for credentials"),
    (r"curl[^\n|]{0,120}\|\s*(ba|z)?sh", "pipes a download into a shell"),
    (r"before (using|calling) (any|this|other) tools?,? (you must|always)", "tool-poisoning style precondition"),
]
TEXT_EXT = re.compile(r"\.(py|kt|kts|java|dart|ts|tsx|js|mjs|json|md|txt|ya?ml|toml|xml|html|sh|swift|gradle|rules)$", re.I)
SKIP = re.compile(r"(^|/)(build|node_modules|\.gradle|\.dart_tool|dist|Pods|vendor|third_party)/|\.min\.js$|"
                  r"(^|/)(tests?|e2e|fixtures?)/")


def check_text(text, path, agent_file):
    findings = []
    locale = bool(LOCALE.search(path))
    for m in HIDDEN.finditer(text):
        ch = m.group(0)
        if ch == "﻿" and m.start() == 0:
            continue  # a byte-order mark at the start is harmless
        if TAGS.match(ch):
            sev, what = "high", "Unicode tag characters (invisible text an LLM still reads)"
        elif BIDI.match(ch):
            sev, what = "high", "bidirectional control characters (Trojan Source)"
        else:
            if locale:
                continue  # zero-width formatting in localized strings is expected
            sev, what = ("medium" if agent_file else "low"), "zero-width characters"
        findings.append(Finding(NAME, "hidden-unicode", sev, "Hidden %s in %s" % (what, path), path,
                                line_of(text, m.start()), category=CATEGORY,
                                detail="Code point U+%04X. Reviewers cannot see it; compilers and models can." % ord(ch),
                                fix="Remove it, or replace with a visible escape if it is intended."))
        break  # one per file is enough
    if agent_file:
        for pattern, why in INJECTION:
            m = re.search(pattern, text, re.I)
            if m:
                findings.append(Finding(NAME, "prompt-injection-text", "medium",
                                        "Instruction-like text an agent will read in %s (%s)" % (path, why), path,
                                        line_of(text, m.start()), category=CATEGORY,
                                        detail="Matched: %r. Fine if you wrote it on purpose; check it if not." % m.group(0)[:80],
                                        fix="Review the file's history for this line."))
    return findings


def check_mcp_config(text, path):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    findings = []
    servers = data.get("mcpServers") or data.get("servers") or {}
    for name, entry in (servers.items() if isinstance(servers, dict) else []):
        if not isinstance(entry, dict):
            continue
        headers = entry.get("headers") or {}
        env = entry.get("env") or {}
        secretish = [k for k, v in list(headers.items()) + list(env.items())
                     if isinstance(v, str) and re.search(r"token|key|secret|auth|bearer|password", k + v, re.I)
                     and not re.search(r"\$\{|\$[A-Z_]+|<.*>|xxx|your[-_]", v, re.I)]
        if secretish:
            findings.append(Finding(NAME, "mcp-config-token", "high",
                                    "MCP server %s in committed %s carries a credential (%s)" % (name, path, ", ".join(secretish)),
                                    path, category=CATEGORY,
                                    fix="Use an env var reference (${VAR}) and keep the real value out of git."))
        url = entry.get("url", "")
        if isinstance(url, str) and url.startswith("http://") and not re.match(r"http://(127\.0\.0\.1|localhost|\[::1\])", url):
            findings.append(Finding(NAME, "mcp-plain-http", "medium", "MCP server %s is reached over plain HTTP" % name,
                                    path, category=CATEGORY, fix="Use HTTPS for any non-loopback MCP server."))
    return findings


def scan(app):
    findings = []
    for f in git_files(app.path):
        if SKIP.search(f) or not (TEXT_EXT.search(f) or AGENT_FILES.search(f)):
            continue
        p = app.path / f
        try:
            if p.stat().st_size > 2_000_000:
                continue
            text = p.read_text(errors="replace")
        except OSError:
            continue
        findings += check_text(text, f, bool(AGENT_FILES.search(f)))
        if re.search(r"(^|/)(\.mcp|mcp|claude_desktop_config|mcp_config)\.json$|(^|/)\.(cursor|vscode)/mcp\.json$", f):
            findings += check_mcp_config(text, f)
    return findings

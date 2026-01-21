import yara
import sqlite3

def load_yara_rules(rules_path):
    rules = yara.compile(filepath=str(rules_path))
    return rules

def run_yara_on_events(rules, events):
    matches = []
    for ev in events:
        data = (ev.get("command_line") or "").encode()
        if rules.match(data=data):
            matches.append(ev)
    return matches

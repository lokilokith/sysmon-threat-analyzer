rules:
  - rule_id: DET-001
    name: Suspicious PowerShell (encoded or download)
    event_id: [1, 3, 11, 22]
    image_any: ["powershell.exe", "pwsh.exe"]
    parent_not_any:
      - "c:\\program files\\splunk\\bin\\python.exe"
      - "c:\\program files\\splunk\\bin\\python3.9.exe"
      - "c:\\windows\\explorer.exe"
    cmdline_contains: ["-enc", "/enc", "downloadstring", "invoke-expression"]
    user_type: interactive
    severity_floor: high
    mitre_id: T1059.001
    mitre_tactic: Execution
    episode_score_factors:
      - factor: encoded_powershell
        score: 30
      - factor: powershell_lolbin
        score: 15

  - rule_id: DET-002
    name: Suspicious cmd.exe LOLBIN
    event_id: [1, 3, 11, 22]
    image_any: ["cmd.exe"]
    parent_not_any:
      - "c:\\windows\\explorer.exe"
    cmdline_contains: ["/c", "/k"]
    user_type: interactive
    severity_floor: high
    mitre_id: T1059.003
    mitre_tactic: Execution
    episode_score_factors:
      - factor: lolbin_execution
        score: 20

  - rule_id: DET-003
    name: LOLBIN network C2 pattern
    event_id: [3]
    image_any:
      - "cmd.exe"
      - "powershell.exe"
      - "pwsh.exe"
      - "rundll32.exe"
      - "mshta.exe"
    requires_external_net: true
    min_events_in_window: 3
    time_window_seconds: 300
    mitre_id: T1071
    mitre_tactic: Command and Control
    episode_score_factors:
      - factor: c2_beaconing_pattern
        score: 30

  - rule_id: DET-004
    name: LOLBIN file creation in user-space
    event_id: [11]
    image_any:
      - "cmd.exe"
      - "powershell.exe"
      - "pwsh.exe"
      - "rundll32.exe"
    path_prefix_any:
      - "c:\\users\\"
      - "c:\\programdata\\"
      - "c:\\windows\\temp\\"
    mitre_id: T1105
    mitre_tactic: Execution
    episode_score_factors:
      - factor: suspicious_drop_location
        score: 25

  - rule_id: DET-005
    name: PowerShell dropper in user/profile folders
    event_id: [11]
    image_any: ["powershell.exe", "pwsh.exe"]
    path_prefix_any:
      - "c:\\users\\"
      - "c:\\programdata\\"
      - "c:\\windows\\temp\\"
    user_type: interactive
    mitre_id: T1059.001
    mitre_tactic: Execution
    episode_score_factors:
      - factor: suspicious_drop_location
        score: 25

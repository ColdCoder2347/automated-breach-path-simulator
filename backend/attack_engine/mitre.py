from __future__ import annotations

import networkx as nx


MITRE_KEYWORDS = [
    {
        "keywords": ["phishing", "macro", "oauth"],
        "tactic": "Initial Access",
        "technique": "Phishing",
        "mitre_id": "T1566",
    },
    {
        "keywords": ["vpn", "leaked", "credential"],
        "tactic": "Initial Access",
        "technique": "Valid Accounts",
        "mitre_id": "T1078",
    },
    {
        "keywords": ["password", "credential", "token", "secret"],
        "tactic": "Credential Access",
        "technique": "Unsecured Credentials",
        "mitre_id": "T1552",
    },
    {
        "keywords": ["kerberos", "ticket"],
        "tactic": "Credential Access",
        "technique": "Steal or Forge Kerberos Tickets",
        "mitre_id": "T1558",
    },
    {
        "keywords": ["admin", "privileged", "domain admin"],
        "tactic": "Privilege Escalation",
        "technique": "Valid Accounts",
        "mitre_id": "T1078",
    },
    {
        "keywords": ["rdp", "remote shell", "smb"],
        "tactic": "Lateral Movement",
        "technique": "Remote Services",
        "mitre_id": "T1021",
    },
    {
        "keywords": ["edr", "disable", "policy"],
        "tactic": "Defense Evasion",
        "technique": "Impair Defenses",
        "mitre_id": "T1562",
    },
    {
        "keywords": ["backup", "ransomware"],
        "tactic": "Impact",
        "technique": "Data Encrypted for Impact",
        "mitre_id": "T1486",
    },
]


def infer_mitre_mapping(edge: dict) -> dict[str, str | None]:
    if edge.get("mitre_tactic") or edge.get("mitre_technique") or edge.get("mitre_id"):
        return {
            "mitre_tactic": edge.get("mitre_tactic"),
            "mitre_technique": edge.get("mitre_technique"),
            "mitre_id": edge.get("mitre_id"),
        }

    label = edge.get("label", "").lower()

    for mapping in MITRE_KEYWORDS:
        if any(keyword in label for keyword in mapping["keywords"]):
            return {
                "mitre_tactic": mapping["tactic"],
                "mitre_technique": mapping["technique"],
                "mitre_id": mapping["mitre_id"],
            }

    return {
        "mitre_tactic": "Execution",
        "mitre_technique": "Exploitation for Client Execution",
        "mitre_id": "T1203",
    }


def path_mitre_chain(graph: nx.DiGraph, path: list[str]) -> list[str]:
    chain = []

    for left, right in zip(path, path[1:]):
        edge = graph.edges[left, right]
        mapping = infer_mitre_mapping(edge)
        tactic = mapping.get("mitre_tactic")
        technique = mapping.get("mitre_technique")
        mitre_id = mapping.get("mitre_id")

        if tactic and technique and mitre_id:
            chain.append(f"{tactic}: {technique} ({mitre_id})")
        elif tactic and technique:
            chain.append(f"{tactic}: {technique}")
        elif tactic:
            chain.append(tactic)

    return chain

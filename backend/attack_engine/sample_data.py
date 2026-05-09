from __future__ import annotations

from backend.attack_engine.schemas import Edge, NetworkData, Node


SAMPLE_NETWORK = NetworkData(
    nodes=[
        Node(id="internet", label="Internet Phishing", type="entry", asset_value=2),
        Node(id="vpn", label="VPN Gateway", type="entry", asset_value=4),
        Node(id="workstation", label="Finance Workstation", type="user", asset_value=5),
        Node(id="ad", label="Active Directory", type="server", asset_value=9),
        Node(id="files", label="File Server", type="server", asset_value=7),
        Node(id="db", label="Customer Database", type="critical", asset_value=10),
        Node(id="backup", label="Backup Vault", type="critical", asset_value=9),
    ],
    edges=[
        Edge(source="internet", target="workstation", label="Phishing macro", cvss=8.1, complexity=3),
        Edge(source="vpn", target="workstation", label="Leaked VPN credential", cvss=7.5, complexity=2),
        Edge(source="workstation", target="ad", label="Cached domain admin token", cvss=9.2, complexity=4),
        Edge(source="workstation", target="files", label="Open SMB share", cvss=6.4, complexity=2),
        Edge(source="ad", target="db", label="Privileged SQL group", cvss=9.8, complexity=3),
        Edge(source="files", target="backup", label="Reused backup password", cvss=8.6, complexity=2),
        Edge(source="ad", target="backup", label="Backup operator delegation", cvss=7.9, complexity=3),
    ],
)

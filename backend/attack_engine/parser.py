from __future__ import annotations

import json
import re
from collections import defaultdict

import networkx as nx

from backend.attack_engine.schemas import (
    Edge,
    NetworkData,
    Node
)

# =========================================================
# GRAPH ENGINE
# =========================================================

graph = nx.DiGraph()

# =========================================================
# REGEX
# =========================================================

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

HOSTNAME_REGEX = (
    r"\b[a-zA-Z0-9._-]+\.(?:local|corp|internal|com|net)\b"
)

CVE_REGEX = r"CVE-\d{4}-\d+"

CVSS_REGEX = r"\bCVSS(?:\s*(?:score|v[0-9.]+))?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.[0-9])?)\b"

SERVICE_REGEX = (
    r"\b(?:ssh|rdp|http|https|ftp|smb|mysql|postgres|redis)\b"
)

ASSET_PHRASE_REGEX = (
    r"\b(?:[A-Za-z0-9_-]+\s+){0,2}"
    r"(?:server|database|gateway|workstation|laptop|vault|firewall|router|switch|portal|runner|console|cluster)\b"
)

# =========================================================
# STOPWORDS
# =========================================================

STOPWORDS = {
    "the",
    "and",
    "that",
    "this",
    "with",
    "from",
    "into",
    "using",
    "through",
    "connects",
    "access",
    "server",
    "network",
    "connection",
    "service",
    "application",
    "system",
    "user",
    "users",
    "port",
    "credential",
    "credentials",
    "password",
    "passwords",
    "leaked",
    "weak",
    "vulnerable",
    "exploit",
    "exploited",
    "reaches"
}

# =========================================================
# CLASSIFICATION
# =========================================================

KEYWORDS = {

    "database": [
        "mysql",
        "postgres",
        "mongodb",
        "redis",
        "database",
        "db"
    ],

    "critical": [
        "vault",
        "finance",
        "payment",
        "critical",
        "admin"
    ],

    "entry": [
        "vpn",
        "internet",
        "external",
        "gateway",
        "firewall"
    ],

    "user": [
        "employee",
        "staff"
    ]
}

# =========================================================
# HELPERS
# =========================================================

def normalize_id(value: str):

    return re.sub(
        r"[^a-zA-Z0-9]+",
        "_",
        value.lower()
    ).strip("_")


def clean_entity_label(value: str):
    cleaned = " ".join(value.split())
    cleaned = re.sub(
        r"^(?:to|from|via|through|into|using|reaches|connects?\s+to)\s+",
        "",
        cleaned,
        flags=re.IGNORECASE
    )
    return cleaned.strip()


def safe_float(value, fallback: float):
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def clamp(value: float, minimum: float, maximum: float):
    return max(minimum, min(maximum, value))


def infer_asset_value(label: str, node_type: str, context: str = ""):
    text = f"{label} {node_type} {context}".lower()
    score = 4.0

    if node_type == "critical":
        score += 3.0
    elif node_type == "database":
        score += 2.0
    elif node_type == "entry":
        score += 0.5

    weighted_keywords = {
        "payment": 2.5,
        "customer": 2.0,
        "finance": 2.0,
        "admin": 2.0,
        "domain controller": 2.5,
        "active directory": 2.5,
        "vault": 2.5,
        "backup": 1.5,
        "production": 1.5,
        "database": 1.5,
        "public": 0.5,
        "test": -1.0,
        "dev": -0.8,
    }

    for keyword, weight in weighted_keywords.items():
        if keyword in text:
            score += weight

    return round(clamp(score, 1, 10), 1)


def extract_cvss(text: str):
    matches = re.findall(CVSS_REGEX, text, flags=re.IGNORECASE)
    if matches:
        return clamp(float(matches[-1]), 0, 10)

    if re.search(CVE_REGEX, text, flags=re.IGNORECASE):
        return 8.8

    lowered = text.lower()
    score = 4.5

    keyword_weights = {
        "critical": 2.8,
        "remote code execution": 3.0,
        "rce": 3.0,
        "privilege escalation": 2.4,
        "credential": 2.0,
        "leaked": 1.8,
        "password": 1.8,
        "public": 1.2,
        "internet": 1.2,
        "exposed": 1.2,
        "unpatched": 1.6,
        "weak": 1.0,
        "misconfigured": 1.0,
        "open": 0.8,
        "segmented": -1.2,
        "mfa": -1.0,
        "patched": -1.4,
        "encrypted": -0.8,
    }

    for keyword, weight in keyword_weights.items():
        if keyword in lowered:
            score += weight

    return round(clamp(score, 0.1, 10), 1)


def infer_complexity(text: str):
    lowered = text.lower()
    score = 4.0

    keyword_weights = {
        "public": -1.0,
        "internet": -1.0,
        "exposed": -1.0,
        "default password": -1.5,
        "leaked": -1.0,
        "open": -0.7,
        "credential": -0.5,
        "mfa": 1.8,
        "segmented": 1.8,
        "firewall": 1.2,
        "vpn": 0.8,
        "requires": 1.0,
        "manual": 0.7,
        "patched": 1.2,
        "hardened": 1.2,
    }

    for keyword, weight in keyword_weights.items():
        if keyword in lowered:
            score += weight

    return round(clamp(score, 1, 10), 1)


def infer_edge_label(sentence: str):
    sentence_lower = sentence.lower()

    service_labels = (
        "ssh",
        "rdp",
        "https",
        "http",
        "smb",
        "sql",
        "mysql",
        "postgres",
        "ftp",
        "redis",
    )

    for service in service_labels:
        if service in sentence_lower:
            return service

    if "credential" in sentence_lower or "password" in sentence_lower:
        return "credential_access"
    if "phishing" in sentence_lower:
        return "phishing"
    if "trust" in sentence_lower or "delegation" in sentence_lower:
        return "trust_relationship"

    return "inferred_relationship"


def extract_json_candidate(text: str):
    stripped = text.strip()

    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped

    start = stripped.find("{")
    end = stripped.rfind("}")

    if start != -1 and end != -1 and end > start:
        return stripped[start:end + 1]

    return None


def classify_node(text: str):

    text = text.lower()

    scores = defaultdict(int)

    for node_type, keywords in KEYWORDS.items():

        for keyword in keywords:

            if keyword in text:
                scores[node_type] += 1

    if scores:
        return max(scores, key=scores.get)

    return "server"


# =========================================================
# ENTITY EXTRACTION
# =========================================================

def extract_entities(text: str):

    entities = []

    phrases = re.findall(
        ASSET_PHRASE_REGEX,
        text,
        re.IGNORECASE
    )

    for phrase in phrases:
        cleaned = clean_entity_label(phrase)
        if cleaned.lower() not in STOPWORDS:
            entities.append(cleaned)

    ips = re.findall(IP_REGEX, text)

    for ip in ips:
        entities.append(ip)

    hosts = re.findall(
        HOSTNAME_REGEX,
        text
    )

    for host in hosts:
        entities.append(host)

    return list(set(entities))


# =========================================================
# NODE EXTRACTION
# =========================================================

def extract_nodes(text: str):

    nodes = {}

    entities = extract_entities(text)

    for value in entities:

        node_id = normalize_id(value)

        if node_id in nodes:
            continue

        nodes[node_id] = Node(
            id=node_id,
            label=value,
            type=classify_node(value),
            asset_value=infer_asset_value(value, classify_node(value), text)
        )

    # safer fallback extraction
    words = re.findall(
        r"\b[a-zA-Z][a-zA-Z0-9._-]{4,}\b",
        text
    )

    for word in words:

        lower = word.lower()

        if lower in STOPWORDS:
            continue

        if lower.startswith("cve"):
            continue

        if len(word) > 40:
            continue

        node_id = normalize_id(word)

        if node_id in nodes:
            continue

        # prevent random english words
        if lower in [
            "therefore",
            "however",
            "because",
            "security",
            "architecture",
            "report"
        ]:
            continue

        nodes[node_id] = Node(
            id=node_id,
            label=word,
            type=classify_node(word),
            asset_value=infer_asset_value(word, classify_node(word), text)
        )

    return nodes


def prune_subsumed_nodes(nodes: dict[str, Node]):
    phrase_labels = [
        node.label.lower()
        for node in nodes.values()
        if " " in node.label
    ]

    removable = []

    for node_id, node in nodes.items():
        label = node.label.lower()

        if " " in label:
            continue

        if any(re.search(rf"\b{re.escape(label)}\b", phrase) for phrase in phrase_labels):
            removable.append(node_id)

    for node_id in removable:
        nodes.pop(node_id, None)

    return nodes


# =========================================================
# RELATIONSHIP INFERENCE
# =========================================================

def infer_edges(
    text: str,
    nodes: dict[str, Node]
):

    edges = []

    seen = set()

    sentences = re.split(
        r"[.\n]",
        text
    )

    for sentence in sentences:

        sentence_lower = sentence.lower()

        sentence_nodes = []

        for node in nodes.values():

            position = sentence_lower.find(node.label.lower())

            if position != -1:
                sentence_nodes.append((position, node))

        if len(sentence_nodes) < 2:
            continue

        sentence_nodes = [
            node
            for _position, node in sorted(
                sentence_nodes,
                key=lambda item: item[0]
            )
        ]

        for i in range(
            len(sentence_nodes) - 1
        ):

            src = sentence_nodes[i]

            dst = sentence_nodes[i + 1]

            if src.id == dst.id:
                continue

            edge_key = (
                src.id,
                dst.id
            )

            if edge_key in seen:
                continue

            seen.add(edge_key)

            edges.append(
                Edge(
                    source=src.id,
                    target=dst.id,
                    label=infer_edge_label(sentence),
                    cvss=extract_cvss(sentence),
                    complexity=infer_complexity(sentence)
                )
            )

    return edges


def infer_sequential_edges(nodes: dict[str, Node]):
    values = list(nodes.values())

    if len(values) < 2:
        return []

    return [
        Edge(
            source=values[index].id,
            target=values[index + 1].id,
            label="inferred_relationship",
            cvss=round((values[index].asset_value + values[index + 1].asset_value) / 2, 1),
            complexity=5.0
        )
        for index in range(len(values) - 1)
    ]


# =========================================================
# GRAPH CLEANING
# =========================================================

def normalize_graph(
    nodes: dict[str, Node],
    edges: list[Edge]
):

    valid_edges = []

    seen = set()

    for edge in edges:

        if edge.source not in nodes:
            continue

        if edge.target not in nodes:
            continue

        if edge.source == edge.target:
            continue

        edge_key = (
            edge.source,
            edge.target
        )

        if edge_key in seen:
            continue

        seen.add(edge_key)

        valid_edges.append(edge)

    return nodes, valid_edges


# =========================================================
# AUTO ENTRY / CRITICAL
# =========================================================

def ensure_special_nodes(
    nodes: dict[str, Node]
):

    values = list(nodes.values())

    if not values:
        return

    if not any(
        n.type == "entry"
        for n in values
    ):
        values[0].type = "entry"

    if not any(
        n.type == "critical"
        for n in values
    ):
        preferred = next(
            (
                node
                for node in values
                if node.type == "database"
                or any(
                    keyword in node.label.lower()
                    for keyword in ("payment", "vault", "critical", "admin", "database")
                )
            ),
            values[-1]
        )
        preferred.type = "critical"
        preferred.asset_value = max(
            preferred.asset_value,
            infer_asset_value(preferred.label, preferred.type)
        )


# =========================================================
# GRAPH BUILDER
# =========================================================

def build_graph(
    nodes: dict[str, Node],
    edges: list[Edge]
):

    graph.clear()

    for node in nodes.values():

        graph.add_node(
            node.id,
            label=node.label,
            type=node.type,
            asset_value=node.asset_value
        )

    for edge in edges:

        graph.add_edge(
            edge.source,
            edge.target,
            label=edge.label,
            cvss=edge.cvss,
            complexity=edge.complexity
        )


# =========================================================
# PDF PARSER
# =========================================================

def parse_structured_topology(raw: dict):
    raw_nodes = raw.get("nodes")
    raw_edges = raw.get("edges")

    if not isinstance(raw_nodes, list) or not isinstance(raw_edges, list):
        return None

    nodes = {}

    for index, item in enumerate(raw_nodes):
        if not isinstance(item, dict):
            continue

        raw_id = item.get("id") or item.get("label") or f"node_{index + 1}"
        node_id = normalize_id(str(raw_id))

        if not node_id:
            node_id = f"node_{index + 1}"

        label = str(item.get("label") or raw_id)
        node_type = str(item.get("type") or classify_node(label))
        asset_context = json.dumps(item)

        nodes[node_id] = Node(
            id=node_id,
            label=label,
            type=node_type,
            asset_value=safe_float(
                item.get("asset_value"),
                infer_asset_value(label, node_type, asset_context)
            ),
        )

    edges = []

    for item in raw_edges:
        if not isinstance(item, dict):
            continue

        source = normalize_id(str(item.get("source", "")))
        target = normalize_id(str(item.get("target", "")))

        if not source or not target or source == target:
            continue

        edge_context = json.dumps(item)

        edge_data = {
            "source": source,
            "target": target,
            "label": str(item.get("label") or "connection"),
            "cvss": safe_float(item.get("cvss"), extract_cvss(edge_context)),
            "complexity": safe_float(item.get("complexity"), infer_complexity(edge_context)),
        }

        for optional_field in (
            "mitre_tactic",
            "mitre_technique",
            "mitre_id",
            "remediation_title",
            "remediation_action",
            "remediation_control",
            "remediation_effort",
            "remediation_cost",
            "remediation_owner",
            "remediation_priority",
        ):
            if optional_field in item:
                edge_data[optional_field] = item[optional_field]

        edges.append(Edge(**edge_data))

    nodes, edges = normalize_graph(nodes, edges)
    ensure_special_nodes(nodes)

    if not nodes:
        raise ValueError("JSON topology did not contain any valid nodes.")

    return NetworkData(
        nodes=list(nodes.values()),
        edges=edges
    )


def parse_text_to_network(text: str):
    json_candidate = extract_json_candidate(text)

    if json_candidate:
        try:
            raw = json.loads(json_candidate)
            structured = parse_structured_topology(raw) if isinstance(raw, dict) else None
            if structured:
                return structured
        except Exception:
            pass

    nodes = extract_nodes(text)
    nodes = prune_subsumed_nodes(nodes)

    edges = infer_edges(
        text,
        nodes
    )

    if not edges:
        edges = infer_sequential_edges(nodes)

    nodes, edges = normalize_graph(
        nodes,
        edges
    )

    ensure_special_nodes(nodes)

    if not nodes:
        raise ValueError("No systems, hosts, services, or topology entities could be extracted.")

    return NetworkData(
        nodes=list(nodes.values()),
        edges=edges
    )


def parse_pdf(
    file_bytes: bytes
):
    try:
        import fitz
    except ModuleNotFoundError as exc:
        raise ValueError(
            "PDF parsing requires PyMuPDF. Run: python -m pip install -r requirements.txt"
        ) from exc

    text = ""

    try:

        pdf = fitz.open(
            stream=file_bytes,
            filetype="pdf"
        )

        for page in pdf:

            extracted = page.get_text()

            if extracted:
                text += extracted + "\n"

    except Exception as e:

        raise ValueError(
            f"PDF parsing failed: {str(e)}"
        )

    if not text.strip():

        raise ValueError(
            "No readable text found"
        )

    network = parse_text_to_network(text)

    build_graph(
        {node.id: node for node in network.nodes},
        network.edges
    )

    return network


# =========================================================
# JSON PARSER
# =========================================================

def parse_json(
    file_bytes: bytes
):

    try:

        raw = json.loads(
            file_bytes.decode()
        )

    except Exception:

        raise ValueError(
            "Invalid JSON"
        )

    if isinstance(raw, dict):
        structured = parse_structured_topology(raw)
        if structured:
            build_graph(
                {node.id: node for node in structured.nodes},
                structured.edges
            )
            return structured

    network = parse_text_to_network(json.dumps(raw))

    build_graph(
        {node.id: node for node in network.nodes},
        network.edges
    )

    return network


# =========================================================
# FILE PARSER
# =========================================================

def parse_file(
    filename: str,
    file_bytes: bytes
):

    ext = filename.split(".")[-1].lower()

    if ext == "pdf":
        return parse_pdf(file_bytes)

    elif ext == "json":
        return parse_json(file_bytes)

    raise ValueError(
        "Unsupported file type"
    )

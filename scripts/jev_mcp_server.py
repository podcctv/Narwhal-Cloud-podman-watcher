#!/usr/bin/env python3
"""
TypeSafe Jev MCP (Model Context Protocol) Server
=================================================
A universal, zero-dependency MCP server providing TypeSafe's System One "Jev"
decision model tools to AI Agents (Antigravity IDE, Claude Code, Cursor, Windsurf, etc.).

Features:
- Pure Python 3.10+ implementation with zero external package dependencies.
- Standard JSON-RPC 2.0 over Stdio (MCP specification 2024-11-05).
- Exposes core Jev decision primitives:
    * jev_choice: Closed-set classification with probabilities & confidence.
    * jev_noul: Calibrated truth probability (0.0 ~ 1.0) for conditions/checks.
    * jev_score: Ordinal scale evaluation & scoring.
    * jev_gate: Safety guardrail check against risk/policy rules.
    * jev_batch: Multi-question parallel evaluation in a single API pass.
"""

import sys
import os
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

# Server Metadata
SERVER_NAME = "typesafe-jev-mcp"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"
DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"


def log(msg: str):
    """Write log messages to stderr so stdout remains clean for MCP JSON-RPC."""
    sys.stderr.write(f"[{SERVER_NAME}] {msg}\n")
    sys.stderr.flush()


def get_api_key() -> Optional[str]:
    """Retrieve TypeSafe API key from environment."""
    return os.environ.get("TYPESAFE_API_KEY") or os.environ.get("JEV_API_KEY")


def call_jev_api(state: Any, questions: Dict[str, Any], model: str = DEFAULT_MODEL) -> Dict[str, Any]:
    """Call TypeSafe System One API via standard library urllib."""
    api_key = get_api_key()
    if not api_key:
        raise ValueError(
            "TYPESAFE_API_KEY is not set. Please configure the TYPESAFE_API_KEY environment variable."
        )

    endpoint = os.environ.get("TYPESAFE_API_BASE", DEFAULT_ENDPOINT)
    payload = {
        "state": state,
        "model": model,
        "questions": questions
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": f"Jev-MCP-Server/{SERVER_VERSION}"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body)
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"TypeSafe API HTTP {e.code} error: {err_msg}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network connection failed: {e.reason}")


# ==============================================================================
# Tool Definitions
# ==============================================================================

TOOLS = [
    {
        "name": "jev_choice",
        "description": (
            "Evaluate a given state/context using TypeSafe Jev model to pick the best "
            "matching candidate from a closed set of choices. Returns the selected choice, "
            "probability distribution across all candidates, and decision confidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "The text, log, code snippet, or JSON state to evaluate."
                },
                "instructions": {
                    "type": "string",
                    "description": "The question or evaluation instruction (e.g., 'What is the root cause of this error?')."
                },
                "candidates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of mutually exclusive candidate options to choose from."
                }
            },
            "required": ["state", "instructions", "candidates"]
        }
    },
    {
        "name": "jev_noul",
        "description": (
            "Evaluate whether a proposition, condition, or question is true given the state/context. "
            "Returns a well-calibrated probability (0.0 to 1.0) and whether it is likely true (>0.5)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "The text, log, code snippet, or JSON state to evaluate."
                },
                "instructions": {
                    "type": "string",
                    "description": "The yes/no condition or proposition (e.g., 'Does this log indicate an urgent production failure?')."
                }
            },
            "required": ["state", "instructions"]
        }
    },
    {
        "name": "jev_score",
        "description": (
            "Rate or assess the state against ordered, descriptive levels (e.g., severity levels, "
            "quality tiers, or priority rankings). Returns the numeric score and confidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "The text, log, code snippet, or JSON state to evaluate."
                },
                "instructions": {
                    "type": "string",
                    "description": "The scoring criteria or evaluation question."
                },
                "levels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Ordered descriptive levels, e.g. ['Low', 'Medium', 'High', 'Critical'] or ['1', '2', '3', '4', '5']."
                }
            },
            "required": ["state", "instructions", "levels"]
        }
    },
    {
        "name": "jev_gate",
        "description": (
            "Safety and guardrail check. Evaluates whether a proposed action, user input, "
            "or command violates a specified safety policy or risk threshold before execution."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_or_content": {
                    "type": "string",
                    "description": "The command, prompt, or action content to inspect."
                },
                "safety_rule": {
                    "type": "string",
                    "description": "The risk or safety policy to check against (e.g., 'Does this command destroy data or delete containers?')."
                },
                "risk_threshold": {
                    "type": "number",
                    "description": "Risk probability threshold above which the action is blocked (default: 0.6).",
                    "default": 0.6
                }
            },
            "required": ["action_or_content", "safety_rule"]
        }
    },
    {
        "name": "jev_batch",
        "description": (
            "Execute multiple Jev questions in parallel over the same state in a single request. "
            "Efficient for combining classification, scoring, and boolean checks together."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "The common state or document to evaluate."
                },
                "questions": {
                    "type": "object",
                    "description": "Map of question_id to question spec. Example: {'is_err': {'type': 'noul', 'instructions': 'Is there an error?'}, 'type': {'type': 'choice', 'instructions': 'Category?', 'candidates': ['A', 'B']}}"
                }
            },
            "required": ["state", "questions"]
        }
    }
]


# ==============================================================================
# Tool Execution Handlers
# ==============================================================================

def execute_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the requested tool and return a JSON-serializable dict."""
    if name == "jev_choice":
        state = arguments.get("state", "")
        instructions = arguments.get("instructions", "")
        candidates = arguments.get("candidates", [])
        if not candidates:
            raise ValueError("candidates list must not be empty.")

        # Convert candidates list to TypeSafe criteria map: option -> null or description
        criteria = {}
        for c in candidates:
            if isinstance(c, dict):
                for k, v in c.items():
                    criteria[str(k)] = v
            else:
                criteria[str(c)] = None

        api_res = call_jev_api(
            state=state,
            questions={"decision": {"type": "choice", "instructions": instructions, "criteria": criteria}}
        )
        ans = api_res.get("answers", {}).get("decision", {})
        return {
            "selected_choice": ans.get("choice"),
            "confidence": ans.get("confidence"),
            "probabilities": ans.get("probabilities", {})
        }

    elif name == "jev_noul":
        state = arguments.get("state", "")
        instructions = arguments.get("instructions", "")

        api_res = call_jev_api(
            state=state,
            questions={"decision": {"type": "noul", "instructions": instructions}}
        )
        ans = api_res.get("answers", {}).get("decision", {})
        noul_val = ans.get("noul", 0.0)
        return {
            "probability": noul_val,
            "is_likely": noul_val >= 0.5
        }

    elif name == "jev_score":
        state = arguments.get("state", "")
        instructions = arguments.get("instructions", "")
        levels = arguments.get("levels", [])
        if not levels:
            raise ValueError("levels list must not be empty.")

        api_res = call_jev_api(
            state=state,
            questions={"decision": {"type": "score", "instructions": instructions, "criteria": levels}}
        )
        ans = api_res.get("answers", {}).get("decision", {})
        return {
            "score": ans.get("score"),
            "confidence": ans.get("confidence"),
            "probabilities": ans.get("probabilities", {}),
            "legend": ans.get("legend", {})
        }

    elif name == "jev_gate":
        content = arguments.get("action_or_content", "")
        safety_rule = arguments.get("safety_rule", "")
        threshold = float(arguments.get("risk_threshold", 0.6))

        api_res = call_jev_api(
            state=content,
            questions={"risk_check": {"type": "noul", "instructions": safety_rule}}
        )
        ans = api_res.get("answers", {}).get("risk_check", {})
        risk_prob = ans.get("noul", 0.0)
        is_blocked = risk_prob >= threshold

        return {
            "allowed": not is_blocked,
            "risk_detected": is_blocked,
            "risk_probability": round(risk_prob, 4),
            "threshold": threshold,
            "verdict": "BLOCKED" if is_blocked else "ALLOWED"
        }

    elif name == "jev_batch":
        state = arguments.get("state", "")
        questions = arguments.get("questions", {})
        if not questions:
            raise ValueError("questions map must not be empty.")

        api_res = call_jev_api(state=state, questions=questions)
        return {
            "answers": api_res.get("answers", {})
        }

    else:
        raise ValueError(f"Unknown tool name: '{name}'")


# ==============================================================================
# MCP Protocol (JSON-RPC 2.0 over Stdio)
# ==============================================================================

def send_response(response_dict: Dict[str, Any]):
    """Format and send JSON-RPC response to stdout followed by newline."""
    data = json.dumps(response_dict, ensure_ascii=False)
    sys.stdout.write(data + "\n")
    sys.stdout.flush()


def handle_request(req: Dict[str, Any]):
    """Process a single incoming JSON-RPC request/notification."""
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    # Handle notifications (no response needed)
    if method == "notifications/initialized":
        log("Client completed initialization handshake.")
        return

    # Handle methods that require a response
    if method == "initialize":
        client_version = params.get("protocolVersion", PROTOCOL_VERSION)
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": client_version if client_version <= PROTOCOL_VERSION else PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
        })

    elif method == "ping":
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        })

    elif method == "tools/list":
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": TOOLS
            }
        })

    elif method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        try:
            result = execute_tool(tool_name, arguments)
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, ensure_ascii=False, indent=2)
                        }
                    ],
                    "isError": False
                }
            })
        except Exception as e:
            log(f"Error executing tool '{tool_name}': {str(e)}")
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Error: {str(e)}"
                        }
                    ],
                    "isError": True
                }
            })

    else:
        # Method not found
        if req_id is not None:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found."
                }
            })


def main():
    """Main loop reading lines from stdin."""
    # Handle simple CLI test argument
    if len(sys.argv) > 1 and sys.argv[1] in ("--test", "-t", "test"):
        api_key = get_api_key()
        print(f"Server: {SERVER_NAME} v{SERVER_VERSION}")
        print(f"Protocol: MCP {PROTOCOL_VERSION}")
        print(f"Tools ({len(TOOLS)}): {', '.join([t['name'] for t in TOOLS])}")
        print(f"API Key configured: {'YES (' + api_key[:4] + '****)' if api_key else 'NO (Set TYPESAFE_API_KEY)'}")
        sys.exit(0)

    log(f"Starting {SERVER_NAME} v{SERVER_VERSION} (stdio mode)...")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            handle_request(req)
        except json.JSONDecodeError as e:
            log(f"Malformed JSON received: {e}")
            send_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error: Invalid JSON."
                }
            })
        except Exception as e:
            log(f"Unexpected server error: {e}")


if __name__ == "__main__":
    main()

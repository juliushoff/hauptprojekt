#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from datetime import date, timedelta


CATALOG = {
    "mcp": "Model Context Protocol connects host applications to external tools and data sources.",
    "sandbox": "A sandbox limits filesystem, network, process, and environment access during execution.",
    "contract": "A capability contract describes what a tool appears allowed and forbidden to do.",
}

WEATHER = {
    "Berlin": {"condition": "partly cloudy", "high_c": 24, "low_c": 15},
    "Hamburg": {"condition": "light rain", "high_c": 21, "low_c": 14},
    "Munich": {"condition": "sunny", "high_c": 27, "low_c": 16},
}

NOTES: list[dict[str, str]] = []


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "calculator"
    tools = tools_for_mode(mode)
    while True:
        message = read_message()
        if message is None:
            return 0
        if "id" not in message:
            continue
        method = message.get("method")
        if method == "initialize":
            write_message({
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": f"benign-{mode}", "version": "0.1.0"},
                },
            })
        elif method == "tools/list":
            write_message({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": tools}})
        elif method == "tools/call":
            params = message.get("params", {})
            result = call_tool(params.get("name", ""), params.get("arguments", {}), mode)
            write_message({"jsonrpc": "2.0", "id": message["id"], "result": result})
        else:
            write_message({
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": f"Unknown method: {method}"},
            })


def tools_for_mode(mode: str) -> list[dict]:
    if mode == "calculator":
        return [
            {
                "name": "calculate",
                "description": "Calculate a simple arithmetic operation on two numeric inputs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "operation": {
                            "type": "string",
                            "enum": ["add", "subtract", "multiply", "divide"],
                            "description": "Arithmetic operation to perform.",
                        },
                        "a": {"type": "number", "description": "First operand."},
                        "b": {"type": "number", "description": "Second operand."},
                    },
                    "required": ["operation", "a", "b"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "convert_temperature",
                "description": "Convert a temperature value between Celsius and Fahrenheit.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "number", "description": "Temperature value to convert."},
                        "from_unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                        "to_unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                    },
                    "required": ["value", "from_unit", "to_unit"],
                    "additionalProperties": False,
                },
            },
        ]
    if mode == "catalog":
        return [
            {
                "name": "search_articles",
                "description": "Search a small built-in article catalog by keyword.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Keyword to search for."}
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_article",
                "description": "Return one built-in article by id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "article_id": {
                            "type": "string",
                            "enum": sorted(CATALOG.keys()),
                            "description": "Article id to retrieve.",
                        }
                    },
                    "required": ["article_id"],
                    "additionalProperties": False,
                },
            },
        ]
    if mode == "weather_static":
        return [
            {
                "name": "get_weather",
                "description": "Return a static weather summary for a supported city.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "city": {
                            "type": "string",
                            "enum": sorted(WEATHER.keys()),
                            "description": "City to look up.",
                        }
                    },
                    "required": ["city"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_forecast_dates",
                "description": "Return the next available static forecast dates.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "days": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 5,
                            "description": "Number of dates to return.",
                        }
                    },
                    "required": ["days"],
                    "additionalProperties": False,
                },
            },
        ]
    if mode == "text_tools":
        return [
            {
                "name": "count_words",
                "description": "Count words and characters in a provided text string.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to analyze."}
                    },
                    "required": ["text"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "normalize_text",
                "description": "Normalize a provided text string by lowercasing and trimming repeated whitespace.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to normalize."}
                    },
                    "required": ["text"],
                    "additionalProperties": False,
                },
            },
        ]
    if mode == "notes_memory":
        return [
            {
                "name": "add_note",
                "description": "Store a short note in process memory for the current MCP session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Short note title."},
                        "body": {"type": "string", "description": "Note body."},
                    },
                    "required": ["title", "body"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_notes",
                "description": "List notes stored in process memory during the current MCP session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            },
        ]
    return []


def call_tool(name: str, args: dict, mode: str) -> dict:
    if mode == "calculator":
        return call_calculator(name, args)
    if mode == "catalog":
        return call_catalog(name, args)
    if mode == "weather_static":
        return call_weather(name, args)
    if mode == "text_tools":
        return call_text_tools(name, args)
    if mode == "notes_memory":
        return call_notes(name, args)
    return text_result("unknown mode", is_error=True)


def call_calculator(name: str, args: dict) -> dict:
    if name == "calculate":
        operation = args.get("operation")
        a = float(args.get("a", 0))
        b = float(args.get("b", 0))
        if operation == "add":
            value = a + b
        elif operation == "subtract":
            value = a - b
        elif operation == "multiply":
            value = a * b
        elif operation == "divide":
            if b == 0:
                return text_result("division by zero", is_error=True)
            value = a / b
        else:
            return text_result("unknown operation", is_error=True)
        return text_result(json.dumps({"operation": operation, "result": value}, sort_keys=True))
    if name == "convert_temperature":
        value = float(args.get("value", 0))
        from_unit = args.get("from_unit")
        to_unit = args.get("to_unit")
        if from_unit == to_unit:
            converted = value
        elif from_unit == "celsius" and to_unit == "fahrenheit":
            converted = value * 9 / 5 + 32
        elif from_unit == "fahrenheit" and to_unit == "celsius":
            converted = (value - 32) * 5 / 9
        else:
            return text_result("unsupported conversion", is_error=True)
        return text_result(json.dumps({"value": round(converted, 2), "unit": to_unit}, sort_keys=True))
    return text_result("unknown tool", is_error=True)


def call_catalog(name: str, args: dict) -> dict:
    if name == "search_articles":
        query = str(args.get("query", "")).lower()
        matches = [
            {"id": article_id, "title": article_id.replace("_", " ").title()}
            for article_id, body in CATALOG.items()
            if query in article_id.lower() or query in body.lower()
        ]
        return text_result(json.dumps({"matches": matches}, sort_keys=True))
    if name == "get_article":
        article_id = str(args.get("article_id", ""))
        body = CATALOG.get(article_id)
        if body is None:
            return text_result("article not found", is_error=True)
        return text_result(json.dumps({"id": article_id, "body": body}, sort_keys=True))
    return text_result("unknown tool", is_error=True)


def call_weather(name: str, args: dict) -> dict:
    if name == "get_weather":
        city = str(args.get("city", ""))
        weather = WEATHER.get(city)
        if weather is None:
            return text_result("city not found", is_error=True)
        return text_result(json.dumps({"city": city, **weather}, sort_keys=True))
    if name == "get_forecast_dates":
        days = int(args.get("days", 1))
        days = max(1, min(days, 5))
        today = date.today()
        dates = [(today + timedelta(days=offset)).isoformat() for offset in range(days)]
        return text_result(json.dumps({"dates": dates}, sort_keys=True))
    return text_result("unknown tool", is_error=True)


def call_text_tools(name: str, args: dict) -> dict:
    text = str(args.get("text", ""))
    if name == "count_words":
        words = [word for word in text.split() if word]
        return text_result(json.dumps({
            "characters": len(text),
            "words": len(words),
        }, sort_keys=True))
    if name == "normalize_text":
        normalized = " ".join(text.lower().split())
        return text_result(json.dumps({"normalized": normalized}, sort_keys=True))
    return text_result("unknown tool", is_error=True)


def call_notes(name: str, args: dict) -> dict:
    if name == "add_note":
        note = {"title": str(args.get("title", "")), "body": str(args.get("body", ""))}
        NOTES.append(note)
        return text_result(json.dumps({"stored": True, "count": len(NOTES)}, sort_keys=True))
    if name == "list_notes":
        return text_result(json.dumps({"notes": NOTES}, sort_keys=True))
    return text_result("unknown tool", is_error=True)


def text_result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def read_message() -> dict | None:
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line == b"":
            return None
        text = line.decode("ascii", errors="replace").strip()
        if not text:
            break
        if ":" in text:
            key, value = text.split(":", 1)
            headers[key.lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode("utf-8"))


def write_message(payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    raise SystemExit(main())

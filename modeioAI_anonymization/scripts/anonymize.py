#!/usr/bin/env python3
"""
Modeio AI anonymization script: calls /api/detector/anonymize to anonymize PII in input text or JSON.
Request format matches the one used in skills/curl.ipynb.
"""

import argparse
import json
import sys

import requests

URL = "https://www.modeio.ai/api/detector/anonymize"

HEADERS = {
    "sec-ch-ua-platform": '"Windows"',
    "Referer": "https://www.modeio.ai/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
    "DNT": "1",
    "Content-Type": "application/json",
    "sec-ch-ua-mobile": "?0",
}



def anonymize(
    raw_input: str,
) -> dict:
    """
    Call the Modeio anonymization API and return the full response JSON.
    """
    payload = {
        "input": raw_input,
        "inputType": 'text',
        "level": 'crossborder',
        "senderCode": 'CN SHA',
        "recipientCode": 'US NYC',
    }
    resp = requests.post(URL, headers=HEADERS, json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(
        description="Anonymize PII in input text/JSON using Modeio AI"
    )
    parser.add_argument(
        "-i", "--input",
        type=str,
        default=None,
    )
    args = parser.parse_args()

    raw_input = args.input

    if not raw_input.strip():
        print("Error: input is empty", file=sys.stderr)
        sys.exit(1)

    try:
        result = anonymize(
            raw_input
        )
    except requests.RequestException as e:
        print(f"Error: API request failed: {e}", file=sys.stderr)
        sys.exit(1)

    if not result.get("success"):
        print("Error: API returned success=false", file=sys.stderr)
        print(json.dumps(result, indent=2, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)

    data = result.get("data", {})
    anonymized = data.get("anonymizedContent", "")
    has_pii = data.get("hasPII", None)


    print("Status: success", file=sys.stderr)
    print("hasPII:", has_pii, file=sys.stderr)
    print(anonymized)


if __name__ == "__main__":
    main()

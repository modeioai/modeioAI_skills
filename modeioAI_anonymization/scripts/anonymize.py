\

import argparse
import json
import sys

import requests

####### Here you can create your own anonymization backend with model api.
URL = "https://www.modeio.ai/api/detector/anonymize"
#######

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

    )
    parser.add_argument(
        "-i", "--input",
        type=str,
        default=None,
    )
    args = parser.parse_args()

    raw_input = args.input

    if not raw_input.strip():

        sys.exit(1)

    try:
        result = anonymize(
            raw_input
        )
    except requests.RequestException as e:

        sys.exit(1)

    if not result.get("success"):

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

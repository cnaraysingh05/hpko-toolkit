#!/usr/bin/env python3
"""Explicit TCP and HTTP(S) checks from a management machine. Default: plan only."""
import argparse
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def valid_host(host):
    if not isinstance(host, str) or not host or len(host) > 253:
        raise ValueError("Invalid target host.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip('.').split('.')
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
            raise ValueError("Use a literal IP or DNS hostname.")
    if '%' in host:
        raise ValueError("IPv6 zone IDs are not supported.")


def validate(data):
    if not isinstance(data, list) or not 1 <= len(data) <= 64:
        raise ValueError("Supply an array of 1..64 explicit checks.")
    names = set()
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("Each check must be an object.")
        name = item.get('name')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', name) or name in names:
            raise ValueError("Each check needs a unique name of 1..60 letters, digits, underscores or hyphens.")
        names.add(name)
        if item.get('type') == 'tcp':
            if set(item) != {'name', 'type', 'host', 'port'}:
                raise ValueError("TCP checks need name, type, host, port.")
            valid_host(item['host'])
            if type(item['port']) is not int or not 1 <= item['port'] <= 65535:
                raise ValueError("TCP port must be an integer 1..65535.")
        elif item.get('type') == 'http':
            if set(item) != {'name', 'type', 'url', 'status'} or not isinstance(item['url'], str):
                raise ValueError("HTTP checks need name, type, url, status.")
            url = urlsplit(item['url'])
            if url.scheme not in ('http', 'https') or not url.hostname or url.username is not None or url.password is not None or url.fragment:
                raise ValueError("Use an http(s) URL without embedded credentials or fragments.")
            if any(ord(c) < 33 or ord(c) == 127 for c in item['url']):
                raise ValueError("URL contains whitespace or control characters.")
            valid_host(url.hostname)
            if url.port is not None and not 1 <= url.port <= 65535:
                raise ValueError("Invalid HTTP port.")
            if type(item['status']) is not int or not 100 <= item['status'] <= 599:
                raise ValueError("Expected HTTP status must be an integer 100..599.")
        else:
            raise ValueError("Check type must be tcp or http.")
    return data


def check(item, timeout):
    result = {'name': item['name'], 'type': item['type'], 'passed': False}
    try:
        if item['type'] == 'tcp':
            with socket.create_connection((item['host'], item['port']), timeout=timeout):
                result.update(passed=True, detail='TCP connection established; application/login not verified.')
        else:
            url = urlsplit(item['url'])
            if url.scheme == 'https':
                connection = http.client.HTTPSConnection(url.hostname, url.port, timeout=timeout, context=ssl.create_default_context())
            else:
                connection = http.client.HTTPConnection(url.hostname, url.port, timeout=timeout)
            try:
                path = url.path or '/'
                if url.query:
                    path += '?' + url.query
                connection.request('GET', path, headers={'User-Agent': 'HorsePlinko-ServiceCheck/1.0'})
                response = connection.getresponse()
                result.update(passed=response.status == item['status'], status=response.status,
                              expected_status=item['status'], detail='Status check only; redirects not followed, body not inspected.')
            finally:
                connection.close()
    except (OSError, ValueError, http.client.HTTPException) as e:
        result['error'] = str(e)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--run', action='store_true', help='Contact only the explicitly listed targets.')
    parser.add_argument('--timeout', type=int, choices=range(1, 31), default=5, metavar='1..30')
    args = parser.parse_args()
    items = validate(json.loads(args.config.read_text(encoding='utf-8-sig')))
    if not args.run:
        print(json.dumps({'mode': 'plan', 'checks': items}, indent=2))
        return 0
    results = [check(item, args.timeout) for item in items]
    print(json.dumps({'utc': datetime.now(timezone.utc).isoformat(), 'checks': results}, indent=2))
    return 0 if all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(2)

"""Minimal client for the Wazuh 4.x logtest Unix socket (no dependencies).

Protocol (wazuh/src/analysisd/logtest): 4-byte little-endian length header
followed by a JSON request; the reply uses the same framing. Used by
tests/test_wazuh_engine.py to evaluate our rules on the *real* engine instead
of only checking XML syntax.
"""
import json
import os
import socket
import struct

SOCKET = os.environ.get('WAZUH_LOGTEST_SOCKET', '/var/ossec/queue/sockets/logtest')


def available():
    return os.path.exists(SOCKET) and os.access(SOCKET, os.R_OK | os.W_OK)


def _recv_exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError('logtest socket closed early')
        data += chunk
    return data


def run(event, log_format='syslog', location='/var/log/test', token=None, timeout=10):
    """Send one event; return (output_dict, token)."""
    params = {'event': event, 'log_format': log_format, 'location': location}
    if token:
        params['token'] = token
    body = json.dumps({'version': 1, 'command': 'log_processing',
                       'parameters': params}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(SOCKET)
        sock.sendall(struct.pack('<I', len(body)) + body)
        size = struct.unpack('<I', _recv_exact(sock, 4))[0]
        reply = json.loads(_recv_exact(sock, size))
    if reply.get('error'):
        raise RuntimeError(f"logtest error {reply['error']}: {reply.get('message')}")
    data = reply['data']
    return data.get('output', {}), data.get('token')


def rule_id(event, log_format='syslog', location='/var/log/test', token=None):
    output, token = run(event, log_format, location, token)
    return output.get('rule', {}).get('id'), output, token

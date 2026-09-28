#!/usr/bin/env python3
"""MikroTik RouterOS syslog emulator for UC-12/UC-13 (owner [CLAUDE], 2026-09-28).

Sends BSD-syslog datagrams exactly like `/system logging action target=remote
bsd-syslog=yes` so the Wazuh manager path (remoted UDP 514 -> mikrotik decoders
-> rules 100401..100422) can be demonstrated without a physical router.
It is NOT a substitute for the real device; the thesis must say which one was used.

Scenarios:
  bruteforce   5 failed logins then a success from the same IP  -> 100401 x4, 100402, 100404
  config       user added / filter rule removed / ntp changed    -> 100406, 100406, 100405
  scan         15 firewall log lines to distinct ports            -> 100410 ..., 100411
  phone        DHCP lease for a randomized-MAC phone              -> 100421
  known        DHCP lease for an inventoried device               -> 100420 (no alert escalation)
  all          everything above

Usage:
  mikrotik_syslog_sim.py --lab MANAGER_IP SCENARIO [--port 514] [--source-ip ROUTER_IP] [--attacker IP]
--source-ip binds the socket to that local address (must exist on the host) so the
manager's <allowed-ips> check is exercised for real.
"""
import argparse
import ipaddress
import random
import socket
import sys
import time

HOST = 'MikroTik'
PRIVATE = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8')]


def stamp():
    return time.strftime('%b %e %H:%M:%S').replace('  ', '  ')


def line(body, pri=134):
    # <134> = facility local0, severity info (RouterOS default for remote action)
    return f'<{pri}>{stamp()} {HOST} {body}'


def scenario(name, attacker, rng):
    if name == 'bruteforce':
        for _ in range(5):
            yield f'system,error,critical login failure for user admin from {attacker} via ssh'
        yield f'system,info,account user admin logged in from {attacker} via ssh'
    elif name == 'config':
        yield 'system,info,account user backdoor added by admin'
        yield 'system,info filter rule removed by admin'
        yield 'system,info ntp client changed by admin'
    elif name == 'scan':
        for port in rng.sample(range(20, 10000), 15):
            yield (f'firewall,info input: in:ether1 out:(unknown 0), src-mac 00:0c:29:de:ad:01, '
                   f'proto TCP (SYN), {attacker}:{rng.randint(40000, 60000)}->192.168.88.1:{port}, len 60')
    elif name == 'phone':
        mac = '%X%s:%02X:%02X:%02X:%02X:%02X' % (rng.randint(0, 15), rng.choice('26AE'),
                                                 *(rng.randint(0, 255) for _ in range(5)))
        yield f'dhcp,info defconf assigned 192.168.88.{rng.randint(100, 250)} for {mac} Galaxy-A54'
    elif name == 'known':
        yield 'dhcp,info defconf assigned 192.168.88.20 for 00:0C:29:AA:BB:01 kali1'
    else:
        raise ValueError(name)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--lab', action='store_true', required=True)
    ap.add_argument('manager')
    ap.add_argument('scenario', choices=['bruteforce', 'config', 'scan', 'phone', 'known', 'all'])
    ap.add_argument('--port', type=int, default=514)
    ap.add_argument('--source-ip')
    ap.add_argument('--attacker', default='192.168.88.66')
    ap.add_argument('--delay', type=float, default=0.2)
    ap.add_argument('--seed', type=int)
    a = ap.parse_args(argv)
    for ip in (a.manager, a.attacker, a.source_ip):
        if ip and not any(ipaddress.ip_address(ip) in n for n in PRIVATE):
            ap.error(f'{ip}: only private lab addresses are accepted')
    if not 1 <= a.port <= 65535:
        ap.error('bad port')
    rng = random.Random(a.seed)
    names = ['bruteforce', 'config', 'scan', 'phone', 'known'] if a.scenario == 'all' else [a.scenario]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if a.source_ip:
        sock.bind((a.source_ip, 0))
    sent = 0
    for n in names:
        for body in scenario(n, a.attacker, rng):
            sock.sendto(line(body).encode(), (a.manager, a.port))
            print(f'[{n}] {body}')
            sent += 1
            time.sleep(a.delay)
    sock.close()
    print(f'sent {sent} datagram(s) to {a.manager}:{a.port}')
    return 0


if __name__ == '__main__':
    sys.exit(main())

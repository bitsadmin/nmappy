import argparse
from datetime import datetime
import socket
import sys
import os.path
import csv
from netaddr import *
import string

VERSION = 0.3
WEB_URL = 'https://github.com/90sled/nmappy/'
MAX_RESULTS_DISPLAY = 30


class Arguments:
    def __init__(self, target, top_ports, ports, timing, verbosity, scan_technique):
        # Target Specification - https://nmap.org/book/man-target-specification.html
        self.targets = {}
        octets = target.split('.')

        # IP address is specified
        contains_invalid_char = [char not in string.digits + '/-,' for octet in octets for char in octet]
        if len(octets) == 4 and True not in contains_invalid_char:
            # - 192.168.0.0/24
            if '/' in octets[3]:
                cidr = IPNetwork(target)
                self.targets = {key: (None, None) for key in [str(ip) for ip in cidr[1:-1]]}
            # - 192.168.0.1-254
            # - 192.168.3-5,7.1 - TODO
            elif '-' in octets[3]:
                (ip_start, ip_end) = map(int, octets[3].split('-'))
                self.targets = {key: (None, None) for key in ['.'.join(octets[0:3] + [str(host)]) for host in xrange(ip_start, ip_end+1)]}
            # 192.168.0.1,103,104
            elif ',' in octets[3]:
                self.targets = {key: (None, None) for key in ['.'.join(octets[0:3] + [str(host)]) for host in octets[3].split(',')]}
            # - 192.168.0.*
            # - 192.168.*.*
            elif '*' in octets:
                ips = [[i for i in xrange(1,255)] if octet == '*' else [octet] for octet in octets]
                self.targets = {key: (None, None) for key in ['.'.join(map(str, [a,b,c,d])) for a in ips[0] for b in ips[1] for c in ips[2] for d in ips[3]]}
            # - 192.168.0.1
            else:
                self.targets = {target: (None, None)}
        # Hostname is specified
        # - myserver.me
        else:
            self.targets = {target: (None, None)}

        # Port Scanning Techniques (-sT or -sU) - https://nmap.org/book/man-port-scanning-techniques.html
        self.proto = 'tcp' if scan_technique == 'T' else 'udp'

        # Ports Specification and Scan Order (-p) and (--top-ports) - https://nmap.org/book/man-port-specification.html
        self.ports = []
        # Use specified ports
        if ports is not None and len(ports) > 0:
            for part in ports.split(','):
                # Port range
                if '-' in part:
                    range = map(int, part.split('-'))
                    for p in xrange(range[0], range[1] + 1):
                        self.ports.append(p)
                # Single port
                else:
                    self.ports.append(int(part))
        # Use top-ports
        else:
            for s in services_top[self.proto]:
                self.ports.append(s)

                if len(self.ports) == top_ports:
                    break

        # Timing (-T)
        self.timing = timing

        # Verbosity
        self.verbosity = verbosity


class AsciiTable:
    def __init__(self, ports=None):
        # Estimate the maximum width required for the PORT column
        if not ports:
            self.maxportwidth = len('65535/tcp')
        else:
            self.maxportwidth = len('%d/tcp' % max(ports))

    def print_heading(self):
        f = '{0: <%d} {1: <6} {2}' % self.maxportwidth
        print f.format('PORT', 'STATE', 'SERVICE')

    def print_line(self, proto, port, state):
        f = '{0: <%d} {1: <6} {2}' % self.maxportwidth
        print f.format('%d/%s' % (port, proto),
                       'open' if state else 'closed',
                       services_lookup[proto][port] if (proto in services_lookup and port in services_lookup[proto]) else '')


def pre_parse_arguments():
    parser = argparse.ArgumentParser(description='NmapPy %.1f ( %s )' % (VERSION, WEB_URL))
    parser.add_argument('target', action='store', help='Can pass hostnames, IP addresses, networks, etc.')
    parser.add_argument('-s', dest='scan_technique', action='store', choices='TU', default='T', help='TCP Connect()/UDP scan')
    parser.add_argument('-p', dest='ports', action='store', help='Only scan specified ports')
    parser.add_argument('--top-ports', dest='top_ports', type=int, default=1000, action='store', help='Scan <number> most common ports')
    parser.add_argument('-F', dest='top_ports', action='store_const', default=False, const=100, help='Fast mode - Scan fewer ports than the default scan')
    parser.add_argument('-T', dest='timing', type=int, choices=[i for i in xrange(1,6)], default=3, action='store', help='Set timing template (higher is faster)')
    parser.add_argument('-v', dest='verbosity', default=0, action='count', help='Increase verbosity level (use -vv or more for greater effect)')
    return parser.parse_args()


def parse_arguments(args):
    return Arguments(args.target, args.top_ports, args.ports, args.timing, args.verbosity, args.scan_technique)


def check_port(host, proto, port, timeout):
    result = False
    try:
        if proto == 'tcp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0/timeout)
        r = sock.connect_ex((host, port))
        if r == 0:
            result = True
        sock.close()
    except Exception, e:
        pass

    return result


def read_services():
    # Read services from file, if available; otherwise the (limited) built-in list will be used
    if os.path.isfile('nmap-services'):
        sfile = csv.reader(open('nmap-services', 'r'), dialect='excel-tab')
        global services
        services = []
        for s in sfile:
            if not str(s[0]).startswith('#'):
                services.append((s[1], s[0], s[2]))

        services = sorted(services, key=lambda s: s[2], reverse=True)

    # -----------------------------------------------------------------------
    # Used to generate the top 50 TCP/UDP for inclusion in the file
    # top_tcp = filter(lambda s: s[0].endswith('tcp'), services)[:50]
    # top_udp = filter(lambda s: s[0].endswith('udp'), services)[:50]
    # combined = sorted(top_tcp + top_udp, key=lambda  s: s[2], reverse=True)
    # -----------------------------------------------------------------------

    # Process list for easier usage
    for s in services:
        (port, proto) = str(s[0]).split('/')
        (port, proto) = (int(port), proto)
        services_lookup[proto][port] = s[1]
        services_top[proto].append(port)


def main():
    # Check syntactic validity of commandline arguments
    args = pre_parse_arguments()

    # Prepare services list
    read_services()

    # Process arguments
    args = parse_arguments(args)

    try:
        # Header
        start_time = datetime.now()
        print '\nStarting NmapPy %.1f ( %s ) at %s' % (VERSION, WEB_URL, start_time.strftime('%Y-%m-%d %H:%M %Z%z'))

        for target in sorted(args.targets):
            ip = socket.gethostbyname(target)
            print 'NmapPy scan report for %s%s' % (target, ' (%s)' % ip if ip != target else '')

            # Results
            table = AsciiTable(args.ports)
            table.print_heading()
            results = []
            for port in args.ports:
                # Perform check and store result
                state = check_port(ip, args.proto, port, args.timing)
                results.append([port, state])

                # Show all if number of ports to check is less than or equal to MAX_RESULTS_DISPLAY
                if len(args.ports) <= MAX_RESULTS_DISPLAY or args.verbosity > 0 or state:
                    table.print_line(args.proto, port, state)

            args.targets[target] = (ip, results)

            # Summary
            # - Closed ports
            if len(args.ports) > MAX_RESULTS_DISPLAY:
                hidden = len(args.ports) - len(filter(lambda r: r[1], results))
                if hidden > 0:
                    print 'Not shown: %d closed ports' % hidden
            print ''

        # - Hosts
        end_time = datetime.now()
        elapsed = (end_time - start_time)
        # TODO: Detect offline hosts
        print 'NmapPy done: %d IP address (%d host up) scanned in %d.%02d seconds' % (len(args.targets), len(args.targets), elapsed.seconds, elapsed.microseconds/10000)

    except KeyboardInterrupt:
        sys.exit(1)


services = [
    ('80/tcp', 'http', '0.484143'),
    ('631/udp', 'ipp', '0.450281'),
    ('161/udp', 'snmp', '0.433467'),
    ('137/udp', 'netbios-ns', '0.365163'),
    ('123/udp', 'ntp', '0.330879'),
    ('138/udp', 'netbios-dgm', '0.297830'),
    ('1434/udp', 'ms-sql-m', '0.293184'),
    ('445/udp', 'microsoft-ds', '0.253118'),
    ('135/udp', 'msrpc', '0.244452'),
    ('67/udp', 'dhcps', '0.228010'),
    ('23/tcp', 'telnet', '0.221265'),
    ('53/udp', 'domain', '0.213496'),
    ('443/tcp', 'https', '0.208669'),
    ('21/tcp', 'ftp', '0.197667'),
    ('139/udp', 'netbios-ssn', '0.193726'),
    ('22/tcp', 'ssh', '0.182286'),
    ('500/udp', 'isakmp', '0.163742'),
    ('68/udp', 'dhcpc', '0.140118'),
    ('520/udp', 'route', '0.139376'),
    ('1900/udp', 'upnp', '0.136543'),
    ('25/tcp', 'smtp', '0.131314'),
    ('4500/udp', 'nat-t-ike', '0.124467'),
    ('514/udp', 'syslog', '0.119804'),
    ('49152/udp', 'unknown', '0.116002'),
    ('162/udp', 'snmptrap', '0.103346'),
    ('69/udp', 'tftp', '0.102835'),
    ('5353/udp', 'zeroconf', '0.100166'),
    ('111/udp', 'rpcbind', '0.093988'),
    ('49154/udp', 'unknown', '0.092369'),
    ('3389/tcp', 'ms-wbt-server', '0.083904'),
    ('110/tcp', 'pop3', '0.077142'),
    ('1701/udp', 'L2TP', '0.076163'),
    ('998/udp', 'puparp', '0.073395'),
    ('996/udp', 'vsinet', '0.073362'),
    ('997/udp', 'maitrd', '0.073247'),
    ('999/udp', 'applix', '0.073230'),
    ('3283/udp', 'netassistant', '0.066072'),
    ('49153/udp', 'unknown', '0.060743'),
    ('445/tcp', 'microsoft-ds', '0.056944'),
    ('1812/udp', 'radius', '0.053839'),
    ('136/udp', 'profile', '0.051862'),
    ('139/tcp', 'netbios-ssn', '0.050809'),
    ('143/tcp', 'imap', '0.050420'),
    ('53/tcp', 'domain', '0.048463'),
    ('2222/udp', 'msantipiracy', '0.047902'),
    ('135/tcp', 'msrpc', '0.047798'),
    ('3306/tcp', 'mysql', '0.045390'),
    ('2049/udp', 'nfs', '0.044531'),
    ('32768/udp', 'omad', '0.044407'),
    ('5060/udp', 'sip', '0.044350'),
    ('8080/tcp', 'http-proxy', '0.042052'),
    ('1025/udp', 'blackjack', '0.041813'),
    ('1433/udp', 'ms-sql-s', '0.036821'),
    ('3456/udp', 'IISrpc-or-vat', '0.036607'),
    ('80/udp', 'http', '0.035767'),
    ('1723/tcp', 'pptp', '0.032468'),
    ('111/tcp', 'rpcbind', '0.030034'),
    ('995/tcp', 'pop3s', '0.029921'),
    ('993/tcp', 'imaps', '0.027199'),
    ('20031/udp', 'bakbonenetvault', '0.025490'),
    ('1026/udp', 'win-rpc', '0.024777'),
    ('7/udp', 'echo', '0.024679'),
    ('5900/tcp', 'vnc', '0.023560'),
    ('1646/udp', 'radacct', '0.023196'),
    ('1645/udp', 'radius', '0.023180'),
    ('593/udp', 'http-rpc-epmap', '0.022933'),
    ('1025/tcp', 'NFS-or-IIS', '0.022406'),
    ('518/udp', 'ntalk', '0.022208'),
    ('2048/udp', 'dls-monitor', '0.021549'),
    ('626/udp', 'serialnumberd', '0.021473'),
    ('1027/udp', 'unknown', '0.019822'),
    ('587/tcp', 'submission', '0.019721'),
    ('8888/tcp', 'sun-answerbook', '0.016522'),
    ('199/tcp', 'smux', '0.015945'),
    ('1720/tcp', 'h323q931', '0.014277'),
    ('465/tcp', 'smtps', '0.013888'),
    ('548/tcp', 'afp', '0.012395'),
    ('113/tcp', 'ident', '0.012370'),
    ('81/tcp', 'hosts2-ns', '0.012056'),
    ('6001/tcp', 'X11:1', '0.011730'),
    ('10000/tcp', 'snet-sensor-mgmt', '0.011692'),
    ('514/tcp', 'shell', '0.011078'),
    ('5060/tcp', 'sip', '0.010613'),
    ('179/tcp', 'bgp', '0.010538'),
    ('1026/tcp', 'LSA-or-nterm', '0.010237'),
    ('2000/tcp', 'cisco-sccp', '0.010112'),
    ('8443/tcp', 'https-alt', '0.009986'),
    ('8000/tcp', 'http-alt', '0.009710'),
    ('32768/tcp', 'filenet-tms', '0.009199'),
    ('554/tcp', 'rtsp', '0.008104'),
    ('26/tcp', 'rsftp', '0.007991'),
    ('1433/tcp', 'ms-sql-s', '0.007929'),
    ('49152/tcp', 'unknown', '0.007907'),
    ('2001/tcp', 'dc', '0.007339'),
    ('515/tcp', 'printer', '0.007214'),
    ('8008/tcp', 'http', '0.006843'),
    ('49154/tcp', 'unknown', '0.006767'),
    ('1027/tcp', 'IIS', '0.006724'),
    ('5666/tcp', 'nrpe', '0.006614'),
    ('646/tcp', 'ldp', '0.006549')
]
services_lookup = {
    'tcp': {},
    'udp': {},
    'sctp': {}
}
services_top = {
    'tcp': [],
    'udp': [],
    'sctp': []
}


if __name__ == '__main__':
    main()

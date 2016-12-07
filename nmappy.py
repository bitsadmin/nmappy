import argparse
from datetime import datetime
import socket
import sys
import os.path
import csv
from netaddr import *
import string
import random

VERSION = 0.41
WEB_URL = 'https://github.com/90sled/nmappy/'
MAX_RESULTS_DISPLAY = 30


# TARGET SPECIFICATION
# URL: https://nmap.org/book/man-target-specification.html
def target_spec(value):
    targets = {}
    octets = value.split('.')

    # IP address is specified
    contains_invalid_char = [char not in string.digits + '/-,' for octet in octets for char in octet]
    if len(octets) == 4 and True not in contains_invalid_char:
        # - 192.168.0.0/24
        if '/' in octets[3]:
            cidr = IPNetwork(value)
            targets = {key: (None, None) for key in [str(ip) for ip in cidr[1:-1]]}
        # - 192.168.0.1-254
        # - 192.168.3-5,7.1 - TODO
        elif '-' in octets[3]:
            (ip_start, ip_end) = map(int, octets[3].split('-'))
            targets = {key: (None, None) for key in
                            ['.'.join(octets[0:3] + [str(host)]) for host in xrange(ip_start, ip_end + 1)]}
        # 192.168.0.1,103,104
        elif ',' in octets[3]:
            targets = {key: (None, None) for key in
                            ['.'.join(octets[0:3] + [str(host)]) for host in octets[3].split(',')]}
        # - 192.168.0.*
        # - 192.168.*.*
        elif '*' in octets:
            ips = [[i for i in xrange(1, 255)] if octet == '*' else [octet] for octet in octets]
            targets = {key: (None, None) for key in
                            ['.'.join(map(str, [a, b, c, d])) for a in ips[0] for b in ips[1] for c in ips[2] for d in
                             ips[3]]}
        # - 192.168.0.1
        else:
            targets = {value: (None, None)}
    # Hostname is specified
    # - myserver.me
    else:
        targets = {value: (None, None)}

    return targets


# SCAN TECHNIQUES
# Implemented: -sT, -sU
# URL: https://nmap.org/book/man-port-scanning-techniques.html
def scan_technique(value):
    if len(value) > 1:
        raise argparse.ArgumentTypeError('Currently a combination of TCP and UDP is not supported.')

    return value


# PORT SPECIFICATION AND SCAN ORDER
# Implemented: -p, --top-ports
# URL: https://nmap.org/book/man-port-specification.html
def port_specification(value):
    ports = []
    # Use specified ports
    if len(value) > 0:
        for part in value.split(','):
            # Port range
            if '-' in part:
                range = map(int, part.split('-'))
                for p in xrange(range[0], range[1] + 1):
                    ports.append(p)
            # Single port
            else:
                ports.append(int(part))

    return ports


# OUTPUT
# Implemented: -oN
# URL: https://nmap.org/book/man-output.html
def output_validate(value):
    if value == 'X':
        raise argparse.ArgumentTypeError('Currently the XML output option is not supported.')

    return value


def parse_arguments():
    parser = argparse.ArgumentParser(description='NmapPy %.2f ( %s )' % (VERSION, WEB_URL), add_help=False)

    # TARGET SPECIFICATION
    target = parser.add_argument_group('TARGET SPECIFICATION')
    target.add_argument('targets',                              action='store', type=target_spec, help='Can pass hostnames, IP addresses, networks, etc.')

    # HOST DISCOVERY
    # -

    # SCAN TECHNIQUES
    scantech = parser.add_argument_group('SCAN TECHNIQUES')
    scantech.add_argument('-s',         dest='scan_technique',  action='store', type=scan_technique, choices='TU', default='T', help='TCP Connect()/UDP scan')

    # PORT SPECIFICATION AND SCAN ORDER
    portspec = parser.add_argument_group('PORT SPECIFICATION AND SCAN ORDER')
    portspec.add_argument('-p',         dest='ports',           action='store', type=port_specification, help='Only scan specified ports')
    portspec.add_argument('--top-ports',dest='top_ports',       action='store', type=int, default=1000, help='Scan <number> most common ports')
    portspec.add_argument('-F',         dest='top_ports',       action='store_const', default=False, const=100, help='Fast mode - Scan fewer ports than the default scan')
    portspec.add_argument('-r',         dest='ports_randomize', action='store_false', help='Scan ports consecutively - don\'t randomize')

    # SERVICE/VERSION DETECTION
    # -

    # SCRIPT SCAN
    # -

    # OS DETECTION
    # -

    # TIMING AND PERFORMANCE
    performance = parser.add_argument_group('TIMING AND PERFORMANCE')
    performance.add_argument('-T',      dest='timing',          action='store', type=int, choices=[i for i in xrange(1,6)], default=3, help='Set timing template (higher is faster)')

    # FIREWALL/IDS EVASION AND SPOOFING
    # -

    # OUTPUT
    output = parser.add_argument_group('OUTPUT')
    output.add_argument('-v',           dest='verbosity',       action='count', default=0, help='Increase verbosity level (use -vv or more for greater effect)')
    output.add_argument('-o',           dest='output_type',     action='store', choices='NX', type=output_validate, help='Output scan in normal/XML')
    output.add_argument('output_file',  help='File name/location')

    # MISC
    misc = parser.add_argument_group('MISC')
    misc.add_argument('-h', '--help', action='help', help='Print this help summary page.')

    # Always show full help when no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


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


def configure_scan(args):
    # Determine protocol based on Port Scanning Technique
    if args.scan_technique == 'T':
        args.proto = 'tcp'
    else:
        args.proto = 'udp'

    # In case no ports are provided, use top-ports
    if not args.ports:
        ports = []
        for s in services_top[args.proto]:
            ports.append(s)

            if len(ports) == args.top_ports:
                break

        args.ports = ports

    # Randomize order of ports
    if args.ports_randomize:
        random.shuffle(args.ports)

    # Output
    if args.output_type == 'N':
        try:
            f = open(args.output_file, 'w', 0)
            args.output = f
        except IOError as e:
            print "I/O error({0}): {1}".format(e.errno, e.strerror)
            sys.exit(1)


def finish_scan(args):
    # Close output file handle
    if args.output:
        args.output.close()


def print_line(line, output):
    print line

    if output:
        output.write(line + '\n')


def main():
    # Check validity of commandline arguments
    args = parse_arguments()

    # Prepare services list
    read_services()

    # Configure scan
    configure_scan(args)

    try:
        # Header
        start_time = datetime.now()
        print ''
        print_line('Starting NmapPy %.2f ( %s ) at %s' % (VERSION, WEB_URL, start_time.strftime('%Y-%m-%d %H:%M %Z%z')), args.output)

        for target in sorted(args.targets):
            ip = socket.gethostbyname(target)
            print_line('NmapPy scan report for %s%s' % (target, ' (%s)' % ip if ip != target else ''), args.output)

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
                    table.print_line(args.proto, port, state, args.output)

            args.targets[target] = (ip, results)

            # Summary per host: Closed ports
            if len(args.ports) > MAX_RESULTS_DISPLAY:
                hidden = len(args.ports) - len(filter(lambda r: r[1], results))
                if hidden > 0:
                    print_line('Not shown: %d closed ports' % hidden, args.output)
            print_line('', args.output)

        # Overall summary
        end_time = datetime.now()
        elapsed = (end_time - start_time)
        # TODO: Detect offline hosts
        print_line('NmapPy done: %d IP address (%d host up) scanned in %d.%02d seconds' % (len(args.targets), len(args.targets), elapsed.seconds, elapsed.microseconds/10000), args.output)

        finish_scan(args)

    except KeyboardInterrupt:
        sys.exit(1)


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

    def print_line(self, proto, port, state, output):
        f = '{0: <%d} {1: <6} {2}' % self.maxportwidth
        print_line(f.format(
                        '%d/%s' % (port, proto),
                        'open' if state else 'closed',
                        services_lookup[proto][port] if (proto in services_lookup and port in services_lookup[proto]) else ''
                   ),
                   output)


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

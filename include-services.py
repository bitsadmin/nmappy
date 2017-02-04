#!/usr/bin/python
#
# This software is provided under under the BSD 3-Clause License.
# See the accompanying LICENSE file for more information.
#
# Utility to integrate list top services from the nmap-services file into the nmappy.py file.
#
# Author:
#  Arris Huijgen

import os, sys, argparse, csv, re

VERSION = 0.1
WEB_URL = 'https://github.com/bitsadmin/nmappy/'


def validate_file(value):
    if not os.path.isfile(value):
        raise argparse.ArgumentTypeError('File \'%s\' does not exist.' % value)

    return value


def validate_number(value):
    try:
        i = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError('\'%s\' is not a number' % value)

    if i == -1:
        i = sys.maxint

    return i


def parse_arguments():
    parser = argparse.ArgumentParser(description='NmapPy services includer %.2f ( %s )' % (VERSION, WEB_URL))
    parser.add_argument('nmappy_file', action='store', type=validate_file, default='nmappy.py', nargs='?', help='File to patch')
    parser.add_argument('nmap_services_file', action='store', type=validate_file, default='nmap-services', nargs='?', help='nmap-services source file')
    parser.add_argument('-i', '--include', dest='number', action='store', type=validate_number, default=50, help='Number of TCP and UDP services to include (default: 50). Use -1 for all.')

    # Always show full help when no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def read_services(nmap_services_file):
    # Read services from file
    print '[+] Reading services from \'%s\'' % nmap_services_file
    sfile = csv.reader(open(nmap_services_file, 'r'), dialect='excel-tab')
    services = []
    for s in sfile:
        if not str(s[0]).startswith('#'):
            services.append((s[1], s[0], s[2]))

    return sorted(services, key=lambda s: s[2], reverse=True)


def update_py(services, nmappy_file, number):
    # Generate lists of top X TCP/UDP ports
    if number != 0:
        print '[+] Generating list of %s TCP/UDP ports' % ('top %d' % number if number < sys.maxint else 'all')
    else:
        print '[+] Removing list of TCP/UDP ports'
    top_tcp = filter(lambda s: s[0].endswith('tcp'), services)[:number]
    top_udp = filter(lambda s: s[0].endswith('udp'), services)[:number]
    combined = sorted(top_tcp + top_udp, key=lambda s: s[2], reverse=True)

    # Generate string to insert
    # Layout:
    # services = [
    #     ('80/tcp', 'http', '0.484143'),
    #     ...
    #     ('646/tcp', 'ldp', '0.006549')
    # ]
    new_services = 'services = [%s%s\n]' % ('\n    ' if len(combined) > 0 else '', ',\n    '.join([str(s) for s in combined]))

    # Replace list of services using regex
    print '[+] Finding and replacing existing list of services'
    with open(nmappy_file, 'r') as f:
        script = f.read()
    pattern = '^services = \[\n(    \(\'[0-9]{1,5}/[udtcp]{3}\', \'[ -~]+\', \'[0-9]\.[0-9]+\'\),?\n)*\]'
    #test = re.search(pattern, script, re.MULTILINE)
    #print test.group(0)
    new_script = re.sub(pattern, new_services, script, flags=re.MULTILINE)

    # Update the ALL_SERVICES_INCLUDED variable
    tag = 'ALL_SERVICES_INCLUDED = %s'
    if number == sys.maxint:
        (b_old, b_new) = ('False', 'True')
    else:
        (b_old, b_new) = ('True', 'False')
    new_script = new_script.replace(tag % b_old, tag % b_new)

    # Update nmappy Python script
    print '[+] Saving updated script to \'%s\'' % nmappy_file
    with open(nmappy_file, 'w') as f:
        f.write(new_script)


def main():
    # Collect input
    args = parse_arguments()

    # Read nmap-services file into memory
    services = read_services(args.nmap_services_file)

    # Update the nmappy Python script with the services
    update_py(services, args.nmappy_file, args.number)


if __name__ == '__main__':
    main()

#!/usr/bin/python
import sys, csv

def read_services(nmap_services_file):
    sfile = csv.reader(open(nmap_services_file, 'r'), dialect='excel-tab')
    services = []
    for s in sfile:
        if not str(s[0]).startswith('#'):
            services.append((s[1], s[0], s[2]))

    return sorted(services, key=lambda s: s[2], reverse=True)

def main():
    if len(sys.argv) == 1:
        print 'usage: topports.py [top # of ports] [optional: tcp|udp]'
        print 'example: topports.py 10 tcp\n'
        print 'TopPorts v1.0 ( https://github.com/bitsadmin/nmappy/ )'
        return -1

    max = 10
    type = 'tcp'
    if len(sys.argv) > 1:
        max = int(sys.argv[1])
    if len(sys.argv) > 2:
        type = sys.argv[2]
    
    # If needed, adjust to path of 'nmap-services' file
    # In Kali: /usr/share/nmap/nmap-services
    services = read_services('nmap-services')
    services = filter(lambda s: s[0].endswith(type), services)
    
    print ','.join([s[0].split('/')[0] for s in services[0:max]])

if __name__ == '__main__': main()

import csv, glob
import sys, warnings
import requests, re, json
from urllib.parse import urljoin
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor

version = 'v0.1'
writer = None
fingerprints = list()
warnings.filterwarnings('ignore')

def_headers = {
    'User-Agent'        : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
    'Accept'            : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language'   : 'en-US,en;q=0.9',
    'Accept-Encoding'   : 'identity',
    'Sec-Fetch-Mode'    : 'navigate',
    'DNT'               : '1',
    'Connection'        : 'close'
}
lackofart = '''
    +---------------------+
    |  K U B E S T A L K  |
    +---------------------+   %s

[!] KubeStalk by RedHunt Labs - A Modern Attack Surface (ASM) Management Company
[!] Author: 0xInfection (RHL Research Team)
[!] Continuously Track Your Attack Surface using https://redhuntlabs.com/nvadr.
'''

def loader(fname: str) -> None:
    '''
    Loads the signatures from JSON
    '''
    global fingerprints
    files = glob.glob(fname+'/*.json')
    for xfile in files:
        with open(xfile, 'r') as rf:
            fingerprints.append(json.load(rf))
    print('[+] Loaded %d signatures to scan.' % len(fingerprints))

def make_request(host: str, path: str, timeout: int, ssl=False) -> str:
    '''
    Makes a HTTP request to the URL specified
    '''
    xurl = urljoin(host, path)
    req = requests.get(xurl, headers=def_headers, timeout=timeout, verify=ssl)
    if req is not None:
        return req.text

def match_fps(path: str, resp: str) -> tuple:
    '''
    Matches the fingerprints per path
    '''
    for x in fingerprints:
        if isinstance(x['path'], list):
            for xpath in x['path']:
                if xpath == path:
                    for rex in x['detector']:
                        if re.search(rex, resp, re.I):
                            return x['name'], x['type'], x['severity']
        else:
            if x['path'] == path:
                for rex in x['detector']:
                    if re.search(rex, resp, re.I):
                        return x['name'], x['type'], x['severity']

def proc_host(host: str, timeout: int, ssl: bool) -> None:
    '''
    Processes a single host
    '''
    print('[*] Processing host:', host)
    global writer
    allpaths = list()

    for fp in fingerprints:
        if isinstance(fp['path'], list):
            allpaths.extend(fp['path'])
        else:
            allpaths.append(fp['path'])

    if '://' not in host:
        print('[-] Scheme not specified, fixing protocol with http (might not work correctly)...')
        host = 'http://' + host

    for path in set(allpaths):
        resp = make_request(host, path, timeout, ssl)
        xfresp = match_fps(path, resp)

        if xfresp:
            print('[!] Found potential issue on %s: %s' % (host, xfresp[0]))
            writer.writerow([host, path, xfresp[0], xfresp[1], xfresp[2]])

def process_hosts(hosts: list, concurrency: int, timeout: int, ssl: bool) -> None:
    '''
    Main wrapper around the engine
    '''
    with ThreadPoolExecutor(max_workers=concurrency) as exec:
        for host in hosts:
            exec.submit(proc_host, str(host), timeout, ssl)

def main():
    '''
    Main function to wrap all of them
    '''
    print(lackofart % version)
    parser = ArgumentParser(usage='./kubestalk.py <url(s)>')
    parser._action_groups.pop()

    required = parser.add_argument_group('Required Arguments')
    optional = parser.add_argument_group('Optional Arguments')

    required.add_argument('urls', nargs='*', help='List of hosts to scan')

    optional.add_argument('-o', '--output', help='Output path to write the CSV file to', dest='output', default='kubestalk-results.csv')
    optional.add_argument('-f', '--sig-dir', help='Signature directory path to load', dest='sig_dir', default='plugins')
    optional.add_argument('-t', '--timeout', help='HTTP timeout value in seconds', dest='timeout', type=int, default=10)
    optional.add_argument('-ua', '--user-agent', help='User agent header to set in HTTP requests', dest='user_agent')
    optional.add_argument('--concurrency', help='No. of hosts to process simultaneously', dest='concurrency', type=int, default=5)
    optional.add_argument('--verify-ssl', help='Verify SSL certificates', dest='ssl', action='store_true', default=False)
    optional.add_argument('--version', help='Display the version of KubeStalk and exit.', dest='version', action='store_true')

    args = parser.parse_args()

    if not args.urls and not args.version:
        print('[-] You must supply at least a single host to scan.')
        sys.exit(1)

    if args.version:
        print('[+] KubeStalk Version:', version)
        sys.exit()

    if args.sig_dir:
        loader(args.sig_dir)

    global writer, def_headers
    xfwriter = open(args.output, 'w+')
    writer = csv.writer(xfwriter)
    writer.writerow(['host', 'path', 'issue', 'type', 'severity'])

    if args.user_agent:
        def_headers['User-Agent'] = args.user_agent

    process_hosts(args.urls, args.concurrency, args.timeout, args.ssl)

    print('[*] Writing results to output file.')
    xfwriter.flush()
    xfwriter.close()
    print('[+] Done.')

if __name__ == '__main__':
    main()

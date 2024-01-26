
import re
import logging
import sys
import ipaddress
from socket import gethostbyname, gaierror
import socket
from email.parser import HeaderParser

try:
    import dns.resolver
except ImportError:
    logging.info("\033[1;31m[!] Failed to import dnspython module. Run 'pip install dnspython'\033[1;m")
    sys.exit()

__author__  = "Ricardo Barbosa Dias"
__version__ = "3.0.0"
__purpose__ = '''Check dmarc policy'''    

logging.basicConfig(level=logging.INFO, filename="/tmp/check-dmarc.log", format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logging.info(f"======================================================")
logging.info(f"[+] Starting execution.....")
logging.info(f"======================================================")


if sys.argv[1]:
    logfile = sys.argv[1]

f = open(logfile, "r")
log_mail=f.read()
f.close()

global X, Y, Z

parser = HeaderParser()
header_mails = parser.parsestr(log_mail)

def check_header_mail():
    for i in header_mails.keys():
        print(f"header_mails[{i}]: {header_mails[i]}")

def is_fqdn(hostname: str) -> bool:
    if not 1 < len(hostname) < 253:
        return False
    if hostname[-1] == '.':
        hostname = hostname[0:-1]
    labels = hostname.split('.')
    fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)
    return all(fqdn.match(label) for label in labels)

def get_aspf(dmarc_record):
    try:
        result = re.search(r'(aspf=\w)', dmarc_record).group().split('=')[1]
        return result
    except:
        return "ERRO"

def get_adkim(dmarc_record):
    try:
        result = re.search(r'(adkim=\w)', dmarc_record).group().split('=')[1]
        return result
    except:
        return "ERROR"
    
def check_dkim():
    try:
        dkim_is_ok = re.search('d=([^\s]+)', header_mails['DKIM-Signature'], re.MULTILINE).group()
        domain_dkim = dkim_is_ok.split(';')[0]
        return domain_dkim
    except:
        print("[+] SPF Alignment PASS - DKIM")
    
def get_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        print("[+] Couldn't resolve the domain {}".format(domain))
        logging.info("[+] Couldn't resolve the domain {}".format(domain))

    for rdata in answers:
        for record1 in rdata.strings:
            # convert bytes to string
            record = str(record1)
            if 'spf1' in record:
                spf_record=record
    if 'spf_record' in locals():
        return spf_record
    else:
        print("[+] {} doesn't support SPF record ".format(domain))
        logging.info("[+] {} doesn't support SPF record ".format(domain))

def get_dmarc_record(dmarc_domain):
    dmarc="_dmarc." + dmarc_domain
    try:
        answers = dns.resolver.resolve(dmarc, 'TXT', raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        print("[+] Couldn't resolve the domain {} getting default values".format(dmarc))
        logging.info("[+] Couldn't resolve the domain {} getting default values".format(dmarc))
         return "DMARC NULL"
        #return "v=DMARC1; p=none; aspf=r; adkim=r; pct=100;"

    for rdata in answers:
        for record1 in rdata.strings:
            # convert bytes to string
            record = str(record1)
            dmarc_record=record
    if 'dmarc_record' in locals():
        return dmarc_record
    else:
        print("[+] {} doesn't support SPF record ".format(dmarc))
        logging.info("[+] {} doesn't support SPF record ".format(dmarc))
        
def check_ip_network(client_ip):
    for network_address in spf_ips:
        if ipaddress.ip_address(client_ip) in ipaddress.ip_network(network_address[4:]):
            return True
    return False

def display_records():
    print(f"X={X}")
    logging.info(f"X: {X}")
    print(f"Y={Y}")
    logging.info(f"Y: {Y}")
    print(f"Z={Z}")
    logging.info(f"Z: {Z}")

def check_spf(spf_record):
    includes_records = []
    global spf_ips
    if 'include' in spf_record:
        includes_records = re.search(r'include.*\s', spf_record).group().split()
    if 'ip4' in spf_record or 'ip6' in spf_record:
        #ips_records = re.findall('(ip4:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', spf_record)
        ips_records = re.findall('(ip4:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', spf_record)
        for ip_address in ips_records:
            spf_ips.append(ip_address)
            
        #ip6_records = re.findall('(ip6:(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:0-9a-f]{1,4}){1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z))', spf_record)
        #for ip6_address in ip6_records:
        #    spf_ips.append(ip6_address)
    if includes_records:           
        for spf_include in includes_records:
            answers = dns.resolver.resolve(spf_include.split(':')[1], 'TXT', raise_on_no_answer=False)
            for rdata in answers:
                resposta=rdata.to_text()
                check_spf(resposta)

##########################################################################
#check_header_mail()
return_path = header_mails['Return-Path'].split('@')[1].split('>')[0]
hostname_client_ip = header_mails['Received'].split()[1]
logging.info(f"Return-path: {header_mails['Return-Path']}")

if is_fqdn(hostname_client_ip):
    client_ip=socket.gethostbyname(hostname_client_ip)
else:
    client_ip=hostname_client_ip
    
logging.info(f"Client ip: {header_mails['Received']}")
    
dmarc_domain=header_mails['From'].split("@")[1]
logging.info(f"DMARC Domain: {dmarc_domain} - Obtain from \"From\" field: {header_mails['From']}")

spf_ips = []
Y=dmarc_domain

if not return_path:
    X=client_ip
else:
    X=return_path

Z = check_dkim().split('=')[1]

logging.info(f"DKIM Domain: {header_mails['DKIM-Signature']}")

# get spf record
spf_record = str(get_spf_record(X))

# generate spf_ips list variable
check_spf(spf_record)
if not check_ip_network(client_ip):
    print("Server " + hostname_client_ip + " dont't present in spf record")
    
Y=header_mails['From'].split("@")[1]
if X == Y:
    display_records()
    print("DMARC pass")
else:
    dmarc_record=get_dmarc_record(dmarc_domain)
    aspf_value=get_aspf(dmarc_record)
    adkim_value=get_adkim(dmarc_record)

    # Se aspf igual a r faça senao SPF aligned fail
    if aspf_value == 'r': 
        # Se X subdomain Y = DMARC pass senao DMARC Fail
        if X in Y:
            display_records()
            print("DMARC pass")
        else:
            # Se X subdomain Z = DMARC pass senao DMARC Fail
            if X in Z:
                display_records()
                print("DMARC pass")
            else:
                display_records()
                print("DMARC Fail")
    else:
        if aspf_value == 'SEM DMARC':
            print("Domain without dmarc record")
        else:
            display_records()
            print("SPF alignment Fail")

logging.info(f"======================================================")
logging.info(f"[+] Finish execution.....")
logging.info(f"======================================================")

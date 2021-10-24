import sys
import re
from bs4 import BeautifulSoup
import urllib.parse
from colorama import init, Fore, Back

init(autoreset=True)

from gevent import monkey

# should be patched before requests import
monkey.patch_all()

import requests
requests.packages.urllib3.disable_warnings()

timeout = 1

patterns = ['leaked_keys']

# module name for printing
sname = 'leaked_keys'
sname = '[' + sname + ']'

scripts_blacklist = ['wp-plugins', 'wp-themes', 'jquery', 'recaptcha', 'https://www.youtube.com/iframe_api', '/bitrix/']

_regex = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2': r"(" \
                       r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                       r"|s3://[a-zA-Z0-9-\.\_]+" \
                       r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                       r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                       r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds': r"(?i)(" \
                      r"password\s*[`=:\"]+\s*[^\s]+|" \
                      r"password is\s*[`=:\"]*\s*[^\s]+|" \
                      r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                      r"passwd\s*[`=:\"]+\s*[^\s]+)",
}


def parse_js_links(html):
    soup = BeautifulSoup(html, features="html.parser")
    return [x['src'] for x in soup.find_all('script', src=True)]


def format_links(links, base_path):
    result = []
    for link in links:
        if 'http' not in link:
            link = urllib.parse.urljoin(base_path, link)
        for black in scripts_blacklist:
            if black in link:
                break
        else:
            result.append(link)
    return result


def extract_keys(js):
    for regex in _regex.items():
        keys = re.findall(regex[1], js)
        if keys:
            return keys


# The class that is used by scanner
class Executor:
    def __init__(self):
        self.allowed_codes = [200, 401, 403]
        print(sname, 'Executor initialized')

    # The scanner invokes this function in every thread when gets a new domain
    # Important arguments are domain and protocol only,
    # others (ip, port) are optional
    #
    # Returns the full url with protocol, domain and path if success or 
    # False if not
    def execute(self, domain, protocol, ip=None, port=None):
        print(sname, f'New domain {domain}, {ip}, {port}, {protocol}')

        path = f"{protocol}://{domain}/"
        try:
            req = requests.get(path, headers={'accept': 'text/html', 'Host': domain}, verify=False)
        except Exception as err:
            print(err)
            return False

        if req.status_code in self.allowed_codes:
            scripts = parse_js_links(req.content)
            scripts = format_links(scripts, path)

            for script in scripts:
                try:
                    req = requests.get(script, verify=False)
                except Exception as err:
                    print(err)
                    return False

                if req.status_code in self.allowed_codes:
                    keys = extract_keys(req.text)
                    if keys:
                        print(sname, Fore.RED + f'SUCCESS!!! {script} {keys}')
                        return script

        return False  # unsuccessfull


# This is for tests to be able to run the script manually
if __name__ == '__main__':
    domain, protocol, ip, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    e = Executor()
    a = e.execute(domain, protocol, ip, port)
    print(a)

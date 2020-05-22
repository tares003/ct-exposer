#!/usr/bin/env python3
import json
import sys
import requests
import re
import argparse
import gevent
import urllib3
from gevent import socket
from gevent.pool import Pool

requests.packages.urllib3.disable_warnings()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GOGGLE_HEADERS = {'Host': 'transparencyreport.google.com',
                  'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36',
                  'Accept': 'application/json, text/plain, */*',
                  'Accept-Language': 'en-US,en;q=0.5',
                  'Accept-Encoding': 'gzip, deflate, br',
                  'Referer': 'https://transparencyreport.google.com',
                  "Sec-Fetch-Site": "same-origin",
                  "Sec-Fetch-Mode": "cors",
                  "Sec-Fetch-Dest": "empty",
                  'Connection': 'keep-alive',
                  "DNT": "1"
                  }


def get_google_cookie():
    """
    gets G cookie
    :return:
    """
    global GOGGLE_HEADERS
    return requests.get("https://transparencyreport.google.com/https/certificates?hl=en_GB", headers=GOGGLE_HEADERS,
                        verify=False).cookies


GOOGLE_COOKIE = get_google_cookie()


def get_dns_history_from_google(session_hash):
    """
    Gets Domains from google DNS history
    :return:
    """
    global GOGGLE_HEADERS, GOOGLE_COOKIE
    res = json.loads(requests.get(
        f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash={session_hash}",
        headers=GOGGLE_HEADERS, verify=False, cookies=GOOGLE_COOKIE).content.decode().lstrip(")]}\'"))
    # (res)
    d =[]
    try:
        for domain in res[0][1][7]:
            if domain.startswith("*."):
                d.append(domain.lstrip("*."))
            else:
                d.append(domain)
    except TypeError:
        return []
    return d


def main(domain, masscanOutput, urlOutput):
    domainsFound = {}
    domainsNotFound = {}
    if (not masscanOutput and not urlOutput):
        print("[+]: Downloading domain list...")
    response = collectResponse(domain)
    google_domains = collect_response_google(domain)

    if (not masscanOutput and not urlOutput):
        print("[+]: Download of domain list complete.")
    domains = collectDomains(response)
    domains.extend(collect_google_domains(google_domains))
    pool = Pool(15)
    greenlet_google = [pool.spawn(get_dns_history_from_google, domain[5]) for domain in
                       google_domains]  # Only the top 5 of google dns history
    pool.join(timeout=1)
    for g_greenlet in greenlet_google:
        result = g_greenlet.value
        if (result):
            domains.extend(result)

    domains = list(set(domains))
    if (not masscanOutput and not urlOutput):
        print("[+]: Parsed %s domain(s) from list." % len(domains))

    greenlets = [pool.spawn(resolve, domain) for domain in domains]
    pool.join(timeout=1)
    for greenlet in greenlets:
        result = greenlet.value
        if (result):
            for ip in result.values():
                if ip != 'none':
                    domainsFound.update(result)
                else:
                    domainsNotFound.update(result)

    if (urlOutput):
        printUrls(sorted(domains))
    if (masscanOutput):
        printMasscan(domainsFound)
    if (not masscanOutput and not urlOutput):
        print("\n[+]: Domains found:")
        printDomains(domainsFound)
        print("\n[+]: Domains with no DNS record:")
        printDomains(domainsNotFound)


def resolve(domain):
    try:
        return ({domain: socket.gethostbyname(domain)})
    except:
        return ({domain: "none"})


def printDomains(domains):
    for domain in sorted(domains):
        print("%s\t%s" % (domains[domain], domain))


def printMasscan(domains):
    iplist = set()
    for domain in domains:
        iplist.add(domains[domain])
    for ip in sorted(iplist):
        print("%s" % (ip))


def printUrls(domains):
    for domain in domains:
        print("https://%s" % domain)


def collect_response_google(domain, data=[], token=None, depth=5, cookies=None):
    global GOOGLE_HEADERS, GOOGLE_COOKIE
    # if not cookies:
    #     cookies = get_google_cookie()

    if depth == 0:  # pagination limit
        return data

    if not domain and token:
        res = requests.get(
            f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p={token}",
            headers=GOGGLE_HEADERS, verify=False, cookies=GOOGLE_COOKIE)
    else:
        domain = domain.replace(" ", "")
        res = requests.get(
            f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain={domain}",
            headers=GOGGLE_HEADERS, verify=False, cookies=GOOGLE_COOKIE)
    res_data = json.loads(res.content.decode().lstrip(")]}\'"))
    if res_data[0][1]:
        data.extend(res_data[0][1])

    if (res_data[0][1]) and res_data[0][3][1]:  # with token
        return collect_response_google(None, data, res_data[0][3][1], depth - 1, GOOGLE_COOKIE)
    else:
        return data


def collectResponse(domain):
    headers = {'Host': 'ctsearch.entrust.com',
               'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Language': 'en-US,en;q=0.5',
               'Accept-Encoding': 'gzip, deflate',
               'Referer': 'https://www.entrust.com/ct-search/',
               'Connection': 'close',
               'Upgrade-Insecure-Requests': '1',
               'Content-Length': '0'}

    url = 'https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=' + domain + '&includeExpired=true&exactMatch=false&limit=5000'
    response = requests.get(url, headers=headers, verify=False)
    return response


def collect_google_domains(domains):
    d = []
    for domain in domains:
        domain = domain[1]
        d.append(domain)
        if domain.startswith("*."):
            d.append(domain.lstrip("*."))
    return d
    #return list(set([domain[1] for domain in domains]))


def collectDomains(response):
    domains = []
    restring = re.compile(r"cn\\u003d(.*?)(\"|,)", re.MULTILINE)
    match = re.findall(restring, response.text)
    if match:
        for domain in match:
            # The following line avoids adding wildcard domains, as they will not resolve.
            if ((domain[0] not in domains) and not (re.search("^\*\.", domain[0]))):
                domains.append(domain[0])
    return domains


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", type=str, required=True, help="domain to query for CT logs, ex: domain.com")
    parser.add_argument("-u", "--urls", default=0, action="store_true",
                        help="ouput results with https:// urls for domains that resolve, one per line.")
    parser.add_argument("-m", "--masscan", default=0, action="store_true",
                        help="output resolved IP address, one per line. Useful for masscan IP list import \"-iL\" format.")
    args = parser.parse_args()
    main(args.domain, args.masscan, args.urls)
    # collect_response_google("google.com")

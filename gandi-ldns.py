#!/usr/bin/env python3


# Standard library
import configparser
import ipaddress
import os
import socket
import sys
from urllib.parse import urljoin
import logging
from ip_resolver import IpResolver, IpResolverError
from datetime import datetime

logging.basicConfig(filename='info.log', filemode='a', format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)


# Third-party
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

MAX_RETRIES = Retry(
    # try again after 5, 10, 20 seconds for specified HTTP status codes
    total=3,
    backoff_factor=10,
    status_forcelist=[408, 429, 500, 502, 503, 504],
)


def get_zone_ip(section, record):
    """Get the current IP from the A record in the DNS zone"""

    endpoint = "domains/%s/records" % section["domain"]
    api_url = urljoin(section["api"], endpoint)

    ip = "0.0.0.0"

    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=MAX_RETRIES))
    apikey = section["apikey"]
    resp = session.get(api_url, headers={"authorization": f"Bearer {apikey}"})
    resp.raise_for_status()

    current_zone = resp.json()

    # There may be more than one A record - we're interested in one with
    # the specific name (typically @ but could be sub domain)
    for rec in current_zone:
        if rec["rrset_type"] == "A" and rec["rrset_name"] == record:
            ip = rec["rrset_values"][0]
            break

    return ip



def change_zone_ip(section, a_name, new_ip):
    """Change the zone record to the new IP"""

    domain = section["domain"]
    apikey = section["apikey"]

    endpoint = "domains/%s/records/%s" % (domain, a_name)
    api_url = urljoin(section["api"], endpoint)

    body = {"items":[{"rrset_type":"A","rrset_values":[new_ip]}]}

    resp = requests.put(api_url, json=body, headers={"authorization": f"Bearer {apikey}", 'content-type': 'application/json'})
    resp.raise_for_status()


def read_config(config_path):
    """Open the configuration file or create it if it doesn't exists"""
    if not os.path.exists(config_path):
        return None
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    return cfg

def ip_echo():
    today = datetime.today().strftime("%Y-%m-%d %H:%M:%S")
    """Returns the current public IP address. Raises an exception if an issue occurs."""
    try:
        ip_resolver = IpResolver(url='https://checkip.amazonaws.com', alt_url='https://monip.io')
        ip = ip_resolver.resolve_ip()
    except IpResolverError as e:
        logging.error("%s - %s [ERROR]" % (today, str(e)), file=sys.stderr)
        raise RuntimeWarning("IP resolver returned an error: %s" % str(e))
    return ip

def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    path = os.path.join(script_dir, "config.txt")
    config = read_config(path)
    if not config:
        sys.exit("please fill in the 'config.txt' file")

    for section in config.sections():
        gandi_records = config[section]["a_name"].split(',')
        for record in gandi_records:
            zone_ip = get_zone_ip(config[section],record)
            current_ip = ip_echo()

            if zone_ip.strip() == current_ip.strip():
                break
            else:
                logging.info(f"DNS Mistmatch detected:  A-record on gandi:{zone_ip} WAN IP:{current_ip} for A record: {record}")
                change_zone_ip(config[section], record, current_ip)
                zone_ip = get_zone_ip(config[section],record)
                logging.info(f"DNS A record update successful - set to: {zone_ip} for A record: {record}")


if __name__ == "__main__":
    main()

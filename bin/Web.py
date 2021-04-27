#!/usr/bin/env python3
# -*-coding:UTF-8 -*

"""
The Web Module
============================

This module tries to parse URLs and warns if some defined contry code are present.

"""

##################################
# Import External packages
##################################
import redis
import pprint
import time
import os
import dns.exception
from pyfaup.faup import Faup
import re
# Country and ASN lookup
from cymru.ip2asn.dns import DNSClient as ip2asn
import socket
import pycountry
import ipaddress

##################################
# Import Project packages
##################################
from module.abstract_module import AbstractModule
from packages import Paste
from packages import lib_refine
from Helper import Process


class Web(AbstractModule):
    """
    Web module for AIL framework
    """

    # Used to prevent concat with empty fields due to url parsing
    def avoidNone(self, a_string):
        if a_string is None:
            return ""
        else:
            return a_string

    def __init__(self):
        """
        Init Web
        """
        super(Web, self).__init__(logger_channel='script:web')

        # REDIS Cache
        self.r_serv2 = redis.StrictRedis(
            host=self.process.config.get("Redis_Cache", "host"),
            port=self.process.config.getint("Redis_Cache", "port"),
            db=self.process.config.getint("Redis_Cache", "db"),
            decode_responses=True)

        # Country to log as critical
        self.cc_critical = self.process.config.get("Url", "cc_critical")

        # FUNCTIONS #

        self.faup = Faup()

        # Protocol file path
        protocolsfile_path = os.path.join(os.environ['AIL_HOME'],
                                          self.process.config.get("Directories", "protocolsfile"))
        # Get all uri from protocolsfile (Used for Curve)
        uri_scheme = ""
        with open(protocolsfile_path, 'r') as scheme_file:
            for scheme in scheme_file:
                uri_scheme += scheme[:-1]+"|"
        uri_scheme = uri_scheme[:-1]

        self.url_regex = "((?i:"+uri_scheme + \
            ")\://(?:[a-zA-Z0-9\.\-]+(?:\:[a-zA-Z0-9\.&%\$\-]+)*@)*(?:(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(?:25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|(?:[a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(?:com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))(?:\:[0-9]+)*(?:/(?:$|[a-zA-Z0-9\.\,\?\'\\\+&%\$#\=~_\-]+))*)"

        self.prec_filename = None

        # Send module state to logs
        self.redis_logger.info(f"Module {self.module_name} initialized")


    def compute(self, message):
        """
        Search for Web links from given message
        """
        # Extract item
        filename, score = message.split()

        domains_list = set()
        hosts_list = set()

        if self.prec_filename is None or filename != self.prec_filename:
            domains_list.clear()
            hosts_list.clear()

            PST = Paste.Paste(filename)
            client = ip2asn()

            detected_urls = PST.get_regex(self.url_regex)
            if len(detected_urls) > 0:
                to_print = f'Web;{PST.p_source};{PST.p_date};{PST.p_name};'
                self.redis_logger.info(f'{to_print}Detected {len(detected_urls)} URL;{PST.p_rel_path}')

            for url in detected_urls:
                
                if url.endswith(".on"):
                    # URL is an onion link skip
                    # TODO send to TOR crawler ?
                    # self.redis_logger.debug("Skip onion link")
                    continue

                self.redis_logger.debug(f"match regex: {url}")

                to_send = f"{url} {PST._get_p_date()} {filename}"
                self.process.populate_set_out(to_send, 'Url')
                self.redis_logger.debug(f"url_parsed: {to_send}")

                self.faup.decode(url)
                domain = self.faup.get_domain()
                subdomain = self.faup.get_subdomain()

                self.redis_logger.debug(f'{url} Published')

                domains_list.add(domain)

                hostl = f'{subdomain}.{domain}' if subdomain else domain

                if hostl not in hosts_list:
                    # test host only once a host in a paste
                    hosts_list.add(hostl)

                    try:
                        socket.setdefaulttimeout(1)
                        ip = socket.gethostbyname(hostl)
                        # If the resolver is not giving any IPv4 address,
                        # ASN/CC lookup is skip.
                        l = client.lookup(ip, qType='IP')
                    except ipaddress.AddressValueError:
                        self.redis_logger.debug(
                            f'ASN/CC lookup failed for IP {ip}')
                        continue
                    except:
                        self.redis_logger.debug(
                            f'Resolver IPv4 address failed for host {hostl}')
                        continue

                    cc = getattr(l, 'cc')
                    asn = ''
                    if getattr(l, 'asn') is not None:
                        asn = getattr(l, 'asn')[2:]  # remobe b'

                    # EU is not an official ISO 3166 code (but used by RIPE
                    # IP allocation)
                    if cc is not None and cc != "EU":
                        countryname = pycountry.countries.get(alpha_2=cc).name
                        self.redis_logger.debug(f'{hostl};{asn};{cc};{countryname}')
                        if cc == self.cc_critical:
                            to_print = f'Url;{PST.p_source};{PST.p_date};{PST.p_name};Detected {hostl} {cc}'
                            self.redis_logger.info(to_print)
                    else:
                        self.redis_logger.debug(f'{hostl};{asn};{cc}')

            A_values = lib_refine.checking_A_record(self.r_serv2,
                                                    domains_list)

            if A_values[0] >= 1:

                pprint.pprint(A_values)
                # self.redis_logger.info('Url;{};{};{};Checked {} URL;{}'.format(
                #     PST.p_source, PST.p_date, PST.p_name, A_values[0], PST.p_rel_path))

        self.prec_filename = filename


if __name__ == '__main__':

    module = Web()
    module.run()

#!/usr/bin/env python3
# -*-coding:UTF-8 -*

"""
The ComboLeakModule
================

This module is consuming the Redis-list created by the Global queue

It apply mail password regex on paste content

"""

##################################
# Import External packages
##################################
import os
import argparse
import time
import re
import sys
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import yaml


##################################
# Import Project packages
##################################
from module.abstract_module import AbstractModule
from packages import Paste
from packages import Item
import regex_helper
import ConfigLoader


class ComboLeak(AbstractModule):
    """
    Combo Leak module for AIL framework
    """

    # REGEX option
    MAX_EXECUTION_TIME = 30


    def __init__(self):
        """
        company_name: str; the name of the company or group (orange, gafa, frenchisp, ...)
        mail_domains: str array; the list of company mail domains (gmail, amazon, hotmail, orange, wanadoo, ...)
        """
        # logger_channel='script:combo'
        super(ComboLeak, self).__init__(logger_channel='script:combo')

        self.domains = self.__init_mail_domains()

        # TODO password could be base64 encoded, should try to decode
        # self.regex_cred = "[a-zA-Z0-9\.\-_]{3,128}@(?i:[a-z0-9](?i:[a-z0-9-]*[a-z0-9])?\.)+(?i:[a-z0-9])(?i:[a-z0-9-]*[a-z0-9])?\s*(?:[\:\|]\s*[a-zA-z0-9&,\.;\+:!?\-_]{6,})"%(domains)
        self.regex_cred = r'[a-zA-Z0-9\.\-_]{3,128}@(?i:[a-z0-9](?i:[a-z0-9-]{0,63}[a-z0-9])?)(?i:\.[a-z0-9][a-z0-9-]{0,12}[a-z0-9]){1,3}\s*(?:[\:\|]\s*[a-zA-z0-9&,\.;\+:!?\-_]{6,})'
        
        # Split credentials in 4 groups: email, domain, domain without TLD, password
        self.regex_split_credentials = r'([a-zA-Z0-9\.\-_]{3,128}@(((?i:[a-z0-9](?i:[a-z0-9-]{0,63}[a-z0-9])?))(?i:\.[a-z0-9][a-z0-9-]{0,12}[a-z0-9]){1,3}))\s*(?:[\:\|]\s*([a-zA-z0-9&,\.;\+:!?\-_]{6,}))'
        # self.regex_split_credentials = r"(.*@((?i:%s)(?:\.\S+))+)\s*(?:[\:\|]\s*(.{6,}))"

        # Add cache for regex
        self.redis_cache_key = regex_helper.generate_redis_cache_key(self.module_name)

        # Checking if a RediSearch index exists
        # https://github.com/RediSearch/redisearch-py

        # LOAD Redis/ARDB Company
        self.db = ConfigLoader.ConfigLoader().get_redis_conn("Redis_Search_Orange")

        self.cipher = self.__init_cipher()

        # Init a Weekly mail found counter wich reset each week
        # self.db.set(self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY, 0)
        # Get the week number of the year
        self.week_day = time.strftime("%U", time.localtime())

        # Send module state to logs
        self.redis_logger.info(f"Module {self.module_name} initialized")


    def __init_mail_domains(self):
        """
        Init Domain list from yaml config file
        """
        result = None

        # combo leak domains file path
        comboleak_filepath = os.path.join(os.environ['AIL_HOME'],
                                          self.process.config.get("ComboLeak", "comboleakfile"))
        # Get all domains from comboleakfile
        with open(comboleak_filepath, 'r') as domains_file:
            result = yaml.safe_load(domains_file)
        
        # Log at start
        for key, value in result.items():
            self.redis_logger.info(f"{key}: {value}")
        
        return result
        

    def __init_cipher(self):
        """
        Init cipher with pubkey
        Enable encryption with the public part of the RSA key
        """
        result = None

        # Get path to pub key in configs/core.cfg default_pubkey path in module section
        pubkey_file = os.path.join(os.environ['AIL_HOME'], self.process.config.get('ComboLeak', 'default_pubkey'))
        
        # Open and read content
        with open(pubkey_file,'r') as file:
            key = RSA.importKey(file.read())
            # Return a cipher object PKCS1OAEP_Cipher that can be used to perform 
            # PKCS#1 OAEP encryption (Public Key Cryptographic Standards)
            result = PKCS1_OAEP.new(key)
        
        return result


    def render_hmac(self, email, password):
        """
        Create a Hash-based Message Authentication Code 
        of the email and password with a salt 
        """
        # Get the current year
        year = time.localtime(time.time()).tm_year
        # Year = datetime.date.today().year
        
        # Create a salt for the hash
        newyear = year + year%13

        # Concat elements of the key
        key = f'{newyear}{email}{password}'
        
        # Generate the Hash-based Message Authentication Code
        # key is encode as a byte string, SHA256 as hash algorithm
        h = HMAC.new(key.encode(), digestmod=SHA256)

        # return the string representation of the hash
        return h.hexdigest()


    def compute(self, message):
        """
        Search for Company crendentials from given message
        """

        # Module stats
        # self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY = 'credentials:%s:indexWeekly'%(self.company_name)    

        # Extract item id and content
        item_id = Item.get_item_id(message)
        # Sanitize all HTML tags
        item_content = Item.get_item_content_beautifulsoup(item_id)
        # Extract all credentials
        all_credentials =  regex_helper.regex_findall(self.module_name, self.redis_cache_key, self.regex_cred, item_id, item_content, max_time=self.MAX_EXECUTION_TIME)

        # if self.week_day < time.strftime("%U", time.localtime()) or self.week_day == 1:
        #     # New Week detected
        #     self.week_day = time.strftime("%U", time.localtime())
        #     self.db.set(self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY, 0)

        nb_all_cred = len(all_credentials)
        if all_credentials and nb_all_cred > 0:
            
            self.redis_logger.info(f'{self.module_name}; Checked {nb_all_cred} credentials found.')

            source = Item.get_source(item_id)
            
            self.redis_logger.warning(f'{self.module_name};{source};{Item.get_item_date(item_id)};{Item.get_item_basename(item_id)};{message};{item_id}')

            self.redis_logger.debug(f'get_item_filename: {Item.get_item_filename(item_id)}')
            self.redis_logger.debug(f'get_item_size: {Item.get_item_size(item_id)}')
            self.redis_logger.debug(f'get_item_nb_duplicates: {Item.get_item_nb_duplicates(item_id)}')
            self.redis_logger.debug(f'get_item_metadata: {Item.get_item_metadata(item_id)}')
       
            # Compute record mapping
            # current date and time
            # now = datetime.timestamp(datetime.now())
            now = int(time.time())

            # Current date in YYMMdd
            now_day = time.strftime("%Y%m%d", time.localtime())

            # Init tag messages to send
            msg_tag = set()

            # Execute redis command in bulk
            with self.db.pipeline() as pipe:
                # TODO stats ?
                for cred in all_credentials:
    
                    # Split credentials in email, domain and password
                    credentials = re.findall(self.regex_split_credentials, cred)
                    self.redis_logger.info(f'credentials: {credentials}')

                    # Extract email domain, domain without TLD and password
                    email, domaintld, domain, password = credentials[0]
                    self.redis_logger.debug(f'email: {email}')
                    self.redis_logger.debug(f'domain TLD: {domaintld}')
                    self.redis_logger.debug(f'domain: {domain}')
                    self.redis_logger.debug(f'password: {password}')
                    
                    # key_id is the hash of salted email+password
                    #   item_id
                    # TODO distinguish uuid key and mail pass hash ?
                    #   get UUID # UUID = str(uuid.uuid4())
                    key_id = self.render_hmac(email, password)
                    self.redis_logger.debug(f'key hashed: {key_id}')

                    # TODO get company name
                    company_name = self.get_company_name(domain)

                    # Add tag to list of message tag if not already added
                    msg_tag.add(f'infoleak:automatic-detection="{company_name}-credentials";{item_id}')

                    # Unique number attached to unique hash tuple email/password
                    # key_index = pipe.sadd(self.REDIS_KEY_CREDENTIALS_INDEX_SET, key_id)
                    # self.redis_logger.debug(f'key index: {key_index}')

                    namespace = f'credentials:{company_name}'
                    # SortedSet of daily found paste
                    pipe.zincrby(f'{namespace}:stat:dailyleak', now_day)

                    # Test if hashed key is already known in SortedSet of hashed keys
                    #   INCRBY returns 1 if hashed key do not exists
                    #                  > 1 if already encountered
                    # Counter of Key_id is directely incremented in the test above
                    # SortedSet of Credentials IDs (Salted email password HMAC)
                    #  not in pipe, should be executed first
                    if 1 == self.db.zincrby(f'comboleak:index', key_id):

                        # Increment Weekly mail found counter
                        # TODO time series
                        # pipe.incr(self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY)
                        # SortedSet of Uniq daily found paste
                        pipe.zincrby(f'{namespace}:stat:dailyleakunicity', now_day)

                        # Index by timestamp
                        pipe.zadd(f'comboleak:timestamp:index', f"{now}", f"{key_id}")
                        # Index by domain
                        pipe.zadd(f'comboleak:domaintld:index', 0, f"{domaintld}:{key_id}")

                        # cipher data with RSA, it return the cipher data
                        cipher_email = self.cipher.encrypt(email.encode())
                        self.redis_logger.debug(f'cipher_email: {cipher_email}')
                        cipher_password = self.cipher.encrypt(password.encode())
                        self.redis_logger.debug(f'cipher_password: {cipher_password}')
                        
                        # Compute record mapping
                        record = {
                            "id" : f"{key_id}",
                            "paste_name": f"{Item.get_item_basename(item_id)}",
                            "paste_path": f"{item_id}",
                            "source": f"{source}",
                            "domain_tld": f"{domaintld}",
                            "cipher_email": f"{cipher_email}",
                            "cipher_password": f"{cipher_password}",
                            "email": f"{email}",
                            "password": f"{password}",
                            "first_seen" : f"{now}",
                            "last_seen" : f"{now}",
                            "checked": 'false'
                        }
                        # Put first seen with the item date ?
                        # "first_seen" : "%s"%(Item.get_item_date(item_id)),

                        # Set key to value within hash name, mapping accepts a dict of key/value pairs that that will be added to hash name. 
                        # Returns the number of fields that were added
                        # Add the mapping between the credential and the path
                        # TODO add TTL
                        # HashSet of all Credentials records
                        # pipe.hmset(f'{namespace}:record:{key_id}', mapping=record)
                        pipe.hmset(f'comboleak:record:{key_id}', mapping=record)

                        # SortedSet for domains (gmail.fr, hotmail.com, other.fr, ...)
                        # Getting domains score:
                        #   REDIS > ZREVRANGE credentials:company_name:domain 0 -1 WITHSCORES
                        # Increment gmail.fr domain score:
                        #   ZINCRBY credentials:company_name:domain 1 gmail.fr
                        # Increment (default 1) domain in sortedset
                        # TODO put in stat redis db
                        pipe.zincrby(f'{namespace}:stat:domain', domaintld.lower(), amount=1)

                        # Increment (default 1) source in sortedset
                        # TODO put in stat redis db
                        pipe.zincrby(f'{namespace}:stat:source', source.lower(), amount=1)

                    else:
                        # Update last_seen of these credentials
                        pipe.hset(f'comboleak:record:{key_id}', "last_seen", now)

                    # self.process.populate_set_out(credentials, 'Company')

                # Send all transactions to redis
                pipe.execute()

            # Send item to duplicate
            self.process.populate_set_out(item_id, 'Duplicate')

            # Send Tag items
            for msg in msg_tag:
                self.process.populate_set_out(msg, 'Tags')
                self.redis_logger.debug(f'Tags: {msg} ')

        else:
            self.redis_logger.debug(f'No {self.module_name} found in this paste: {item_id}')


    def get_company_name(self, domain):
        """
        Return the name of the company for the given domain if known, 
        else return misc for company name
        """
        company = 'misc'

        for key, value in self.domains.items():
            if domain in value:
                company = key
                continue

        self.redis_logger.debug(f'domain {domain} is associated to: {company}')

        return company.lower()


if __name__ == '__main__':
    
    module = ComboLeak()
    module.run()

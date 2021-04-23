#!/usr/bin/env python3
# -*-coding:UTF-8 -*

"""
The CompanyCredentialsModule
================

This module is consuming the Redis-list created by the Global queue

It apply mail password regex on paste content

"""

##################################
# Import External packages
##################################
import os
import time
import re
import sys
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


##################################
# Import Project packages
##################################
from module.abstract_module import AbstractModule
from packages import Paste
from packages import Item
import regex_helper
import ConfigLoader


class CompanyCredentials(AbstractModule):
    """
    Company Credentials module for AIL framework
    """

    # REGEX option
    MAX_EXECUTION_TIME = 30


    def __init__(self, company_name, queue_name, mail_domains):
        """
        company_name: str; the name of the company or group (orange, gafa, frenchisp, ...)
        mail_domains: str array; the list of company mail domains (gmail, amazon, hotmail, orange, wanadoo, ...)
        """
        super(CompanyCredentials, self).__init__(company_name, queue_name)

        self.company_name = company_name.lower()
        
        domains = '|'.join(mail_domains)
        # TODO password could be base64 encoded, should try to decode
        self.regex_cred = "[a-zA-Z0-9\.\-_]{3,128}(?:@(?i:%s))(?:\.[a-zA-Z0-9](?:[\.a-zA-Z]{0,3}))+\s*(?:[\:\|]\s*[a-zA-z0-9&,\.;\+:!?\-_]{6,})"%(domains)

        # Split credentials in 3 groups: email, domain, password
        self.regex_split_credentials = r"(.*@((?i:%s)(?:\.\S+))+)\s*(?:[\:\|]\s*(.{6,}))"%(domains)
        self.file_logger.info("Module %s regex %s"%(self.module_name, self.regex_split_credentials))

        ###
        # Redis Keys data structures for module Company Credentials
        ###
        # Module stats
        self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY = 'credentials:%s:indexWeekly'%(self.company_name)

        # SortedSet of Credentials IDs (Salted email password HMAC)
        self.REDIS_KEY_CREDENTIALS_INDEX_SORTEDSET = 'credentials:%s:index'%(self.company_name)

        # HashSet of all Credentials records
        self.REDIS_KEY_CREDENTIALS_RECORDS_HASH = 'credentials:%s:record'%(self.company_name)

        # SortedSet for domains (gmail.fr, hotmail.com, other.fr, ...)
        # Getting domains score:
        #   REDIS > ZREVRANGE credentials:company_name:domain 0 -1 WITHSCORES
        # Increment gmail.fr domain score:
        #   ZINCRBY credentials:company_name:domain 1 gmail.fr
        # TODO put in stat redis db
        self.REDIS_KEY_CREDENTIALS_DOMAIN_SORTEDSET = 'credentials:%s:stat:domain'%(self.company_name)

        # TODO put in stat redis db
        self.REDIS_KEY_CREDENTIALS_SOURCE_SORTEDSET = 'credentials:%s:stat:source'%(self.company_name)

        # SortedSet of daily found paste
        self.REDIS_KEY_CREDENTIALS_DAILYLEAK_SORTEDSET = 'credentials:%s:stat:dailyleak'%(self.company_name)

        # Add cache for regex
        self.redis_cache_key = regex_helper.generate_redis_cache_key(self.company_name)

        # LOAD Redis/ARDB Company
        self.db = ConfigLoader.ConfigLoader().get_redis_conn("ARDB_Orange")

        self.cipher = self.__init_cipher()

        # Init a Weekly mail found counter wich reset each week
        # self.db.set(self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY, 0)
        # Get the week number of the year
        self.week_day = time.strftime("%U", time.localtime())

        # Send module state to logs
        self.redis_logger.info("Module %s initialized"%(self.module_name))
        self.file_logger.info("Module %s initialized"%(self.module_name))


    def __init_cipher(self):
        """
        Init cipher with pubkey
        Enable encryption with the public part of the RSA key
        """
        result = None

        # Get path to pub key in configs/core.cfg default_pubkey path in module section
        pubkey_file = os.path.join(os.environ['AIL_HOME'], self.process.config.get('CompanyCredentials', 'default_pubkey'))
        
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
        key = '%s%s%s'%(newyear, email, password)
        
        # Generate the Hash-based Message Authentication Code
        # key is encode as a byte string, SHA256 as hash algorithm
        h = HMAC.new(key.encode(), digestmod=SHA256)

        # return the string representation of the hash
        return h.hexdigest()


    def compute(self, message):
        """
        Search for Company crendentials from given message
        """
        # Extract item id and content
        item_id = Item.get_item_id(message)
        # Sanitize all HTML tags
        item_content = Item.get_item_content_beautifulsoup(item_id)
        # Extract all credentials
        all_credentials =  regex_helper.regex_findall(self.company_name, self.redis_cache_key, self.regex_cred, item_id, item_content, max_time=self.MAX_EXECUTION_TIME)
        # publisher.debug('all_credentials: %s'%(all_credentials))
        # self.file_logger.debug('all_credentials: %s'%(all_credentials))
        if self.week_day < time.strftime("%U", time.localtime()) or self.week_day == 1:
            # New Week detected
            self.week_day = time.strftime("%U", time.localtime())
            self.db.set(self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY, 0)

        if all_credentials and len(all_credentials) > 0:
            print('%s; Checked %d credentials found.'%(self.module_name, len(all_credentials)))

            source = Item.get_source(item_id)

            self.redis_logger.info('%s; Checked %d credentials found.'%(self.module_name, len(all_credentials)))
            self.redis_logger.debug('%s;%s;%s;%s;%s;%s'%(self.module_name, source, Item.get_item_date(item_id), Item.get_item_basename(item_id), message, item_id))
            self.file_logger.debug('%s;%s;%s;%s;%s;%s'%(self.module_name, source, Item.get_item_date(item_id), Item.get_item_basename(item_id), message, item_id))
            # self.file_logger.debug('get_item_username: %s '%(Item.get_item_username(item_id)))
            # self.file_logger.debug('get_item_decoded: %s '%(Item.get_item_decoded(item_id)))
            # self.file_logger.debug('get_item_domain: %s '%(Item.get_item_domain(item_id)))
            # self.file_logger.debug('get_item_duplicate: %s '%(Item.get_item_duplicate(item_id)))
            # self.file_logger.debug('get_item_duplicates_dict: %s '%(Item.get_item_duplicates_dict(item_id)))
            # self.file_logger.debug('get_item_encoding: %s '%(Item.get_item_encoding(item_id)))
            self.redis_logger.debug('get_item_filename: %s '%(Item.get_item_filename(item_id)))
            self.redis_logger.debug('get_item_size: %s '%(Item.get_item_size(item_id)))
            self.redis_logger.debug('get_item_nb_duplicates: %s '%(Item.get_item_nb_duplicates(item_id)))
            self.redis_logger.debug('get_item_metadata: %s '%(Item.get_item_metadata(item_id)))
            self.file_logger.debug('get_item_filename: %s '%(Item.get_item_filename(item_id)))
            self.file_logger.debug('get_item_size: %s '%(Item.get_item_size(item_id)))
            self.file_logger.debug('get_item_nb_duplicates: %s '%(Item.get_item_nb_duplicates(item_id)))
            self.file_logger.debug('get_item_metadata: %s '%(Item.get_item_metadata(item_id)))
            # self.file_logger.debug('get_item_har_name: %s '%(Item.get_item_har_name(item_id)))
            # self.file_logger.debug('get_item_pgp_mail: %s '%(Item.get_item_pgp_mail(item_id)))
            # self.file_logger.debug('get_item_list_desc: %s '%(Item.get_item_list_desc(item_id)))
            
            # Send item to duplicate
            self.process.populate_set_out(item_id, 'Duplicate')

            # Tag item
            msg = 'infoleak:automatic-detection="%s-credentials";%s'%(self.company_name, item_id)
            self.process.populate_set_out(msg, 'Tags')
            self.redis_logger.debug('Tags: %s '%(msg))
            self.file_logger.debug('Tags: %s '%(msg))
            
            # Compute record mapping
            # current date and time
            # now = datetime.timestamp(datetime.now())
            now = int(time.time())

            # Current date in YYMMdd
            now_day = time.strftime("%Y%m%d", time.localtime())

            # TODO stats ?
            for cred in all_credentials:
 
                # Split credentials in email, domain and password
                credentials = re.findall(self.regex_split_credentials, cred)
                self.redis_logger.info('credentials: %s'%(credentials))
                self.file_logger.debug('credentials: %s'%(credentials))

                # Extract email and password
                email, domain, password = credentials[0]
                self.redis_logger.info('email: %s'%(email))
                self.redis_logger.info('domain: %s'%(domain))
                self.redis_logger.info('password: %s'%(password))

                self.file_logger.debug('email: %s'%(email))
                self.file_logger.debug('domain: %s'%(domain))
                self.file_logger.debug('password: %s'%(password))
                
                # key_id is the hash of salted email+password
                #   item_id
                # TODO distinguish uuid key and mail pass hash ?
                #   get UUID # UUID = str(uuid.uuid4())
                key_id = self.render_hmac(email, password)
                self.redis_logger.debug('key hashed: %s'%(key_id))
                self.file_logger.debug('key hashed: %s'%(key_id))

                # Unique number attached to unique hash tuple email/password
                # key_index = self.db.sadd(self.REDIS_KEY_CREDENTIALS_INDEX_SET, key_id)
                # self.redis_logger.debug('key index: %s'%(key_index))
                # self.file_logger.debug('key index: %s'%(key_index))

                self.db.zincrby(self.REDIS_KEY_CREDENTIALS_DAILYLEAK_SORTEDSET, now_day)

                # Test if hashed key is already known in SortedSet of hashed keys
                #   INCRBY returns 1 if hashed key do not exists
                #                  > 1 if already encountered
                # Counter of Key_id is directely incremented in the test above 
                if 1 == self.db.zincrby(self.REDIS_KEY_CREDENTIALS_INDEX_SORTEDSET, key_id):

                    # Increment Weekly mail found counter
                    # TODO time series
                    self.db.incr(self.REDIS_KEY_CREDENTIALS_INDEX_WEEKLY)

                    # cipher data with RSA, it return the cipher data
                    cipher_email = self.cipher.encrypt(email.encode())
                    self.redis_logger.debug('cipher_email: %s'%(cipher_email))
                    self.file_logger.debug('cipher_email: %s'%(cipher_email))
                    cipher_password = self.cipher.encrypt(password.encode())
                    self.redis_logger.debug('cipher_password: %s'%(cipher_password))
                    self.file_logger.debug('cipher_password: %s'%(cipher_password))
                    
                    # Compute record mapping
                    record = {
                        "pasteName": "%s"%(Item.get_item_basename(item_id)),
                        "source": "%s"%(source),
                        "cipher_email": "%s"%(cipher_email),
                        "cipher_password": "%s"%(cipher_password),
                        "first_seen" : "%s"%(now),
                        "last_seen" : "%s"%(now),
                        "checked": 'false'
                    }
                    # Put first seen with the item date ?
                    # "first_seen" : "%s"%(Item.get_item_date(item_id)),

                    # Set key to value within hash name, mapping accepts a dict of key/value pairs that that will be added to hash name. 
                    # Returns the number of fields that were added
                    # Add the mapping between the credential and the path
                    # TODO add TTL 
                    self.db.hmset('%s:%s'%(self.REDIS_KEY_CREDENTIALS_RECORDS_HASH,key_id), mapping=record)

                    # Increment (default 1) domain in sortedset
                    self.db.zincrby(self.REDIS_KEY_CREDENTIALS_DOMAIN_SORTEDSET, domain.lower(), amount=1)

                    # Increment (default 1) source in sortedset
                    self.db.zincrby(self.REDIS_KEY_CREDENTIALS_SOURCE_SORTEDSET, source.lower(), amount=1)

                else:
                    # Update last_seen of these credentials
                    self.db.hset('%s:%s'%(self.REDIS_KEY_CREDENTIALS_RECORDS_HASH,key_id), "last_seen", now)

                self.process.populate_set_out(credentials, 'Company')
        else:
            self.redis_logger.debug('No %s found in this paste: %s'%(self.module_name, item_id))
            self.file_logger.debug('No %s found in this paste: %s'%(self.module_name, item_id))


# if __name__ == '__main__':
    
#     module = CompanyCredentials('GafaCredentials')
#     module.run()

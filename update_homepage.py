# -*- coding: UTF-8 -*-
import requests
from pprint import pprint as pp
import json
import logging
import logging.config
import re
import yaml
logging.getLogger("urllib3").setLevel(logging.WARNING)

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class LookerApi(object):

    def __init__(self, token, secret, host):
        logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
        self.logger = logging.getLogger(__name__)
        self.logger.propagate = 0
        self.api_logger = logging.getLogger('lookerapi')
        self.token = token
        self.secret = secret
        self.host = host

        self.session = requests.Session()
        self.session.verify = False
        self.session.trust_env = False

        self.auth()

    def auth(self):
        self.api_logger.info('Authenticating')
        url = '{}{}'.format(self.host,'login')
        params = {'client_id':self.token,
                  'client_secret':self.secret}
        self.api_logger.info('Request to %s => POST /api/3.1/login, %s', self.host, {key: (value if key == 'client_id' else "[FILTERED]") for key,value in params.items()})
        r = self.session.post(url,params=params)
        access_token = r.json().get('access_token')
        head = {'Authorization': 'token {}'.format(access_token)}
        self.head = head
        self.session.headers.update(head)
        if r.status_code == requests.codes.ok:
            self.api_logger.info('Request Complete: %s', r.status_code)
        else:
            self.api_logger.warning('Request Complete: %s', r.status_code)
            print('Authentication Error: Check supplied credentials.')
            sys.exit(1)
        return

    def get_homepage_item(self, homepage_item_id):
        url = '{}{}/{}'.format(self.host,'homepage_items', homepage_item_id)
        self.api_logger.info('Request to %s => GET /api/3.1/homepage_items/%s',
                             self.host,
                             homepage_item_id)
        r = self.session.get(url, headers=self.session.headers)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logger.warning('Request Complete: %s', r.status_code)
            print("Error: " + str(e))
            return
        self.api_logger.info('Request Complete: %s', r.status_code)
        return r.json()

    def update_homepage_item(self, homepage_item_id, body):
        url = '{}{}/{}'.format(self.host,'homepage_items', homepage_item_id)
        self.api_logger.info('Request to %s => PATCH /api/3.1/homepage_items/%s',
                             self.host,
                             homepage_item_id)
        r = self.session.patch(url,data=body, headers=self.session.headers)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logger.warning('Request Complete: %s', r.status_code)
            print("Error: " + str(e))
            return
        self.api_logger.info('Request Complete: %s', r.status_code)

    def get_look(self, look_id):
        url = '{}{}/{}/run/json'.format(self.host,'looks', look_id)
        self.api_logger.info('Request to %s => GET /api/3.1/looks/%s/run/json',
                             self.host,
                             look_id)
        r = self.session.get(url, headers=self.session.headers)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            self.logger.warning('Request Complete: %s', r.status_code)
            print("Error: " + str(e))
            return
        self.api_logger.info('Request Complete: %s', r.status_code)
        return r.json()
### ------- HERE ARE PARAMETERS TO CONFIGURE -------

host = 'cs_eng'

homepage_item_id = 8
look_id = 14
field_name = 'orders.created_time'


### ------- OPEN THE CONFIG FILE and INSTANTIATE API -------

f = open('config.yml')
params = yaml.load(f)
f.close()

my_host = params['hosts'][host]['host']
my_secret = params['hosts'][host]['secret']
my_token = params['hosts'][host]['token']

looker = LookerApi(host=my_host,
                  token=my_token,
                  secret = my_secret)

look_info = looker.get_look(look_id)[0][field_name]
item_body =  looker.get_homepage_item(homepage_item_id)
item_body['custom_description'] = 'Data last updated: {}'.format(str(look_info))
looker.update_homepage_item(homepage_item_id, json.dumps(item_body))

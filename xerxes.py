#!/usr/bin/env python3

#  Copyright (c) 2019. Brandon Blackburn - https://keybase.io/blackburnhax, Apache License, Version 2.0.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
#  either express or implied. See the License for the specific
#  language governing permissions and limitations under the License.
#  TL;DR:
#  For a human-readable & fast explanation of the Apache 2.0 license visit:  http://www.tldrlegal.com/l/apache2

from sys import version_info
import getpass
import requests
import sys
import json
import sys
import re
import os
import errno
import tempfile
import hashlib
import time
import ipaddress
import math
import zlib
import base64
import datetime
import pprint
import paramiko
from io import StringIO
import collections
import struct
from dateutil.relativedelta import relativedelta
from modblack2 import get_working_dir, http_status_code, is_dir_writable, progress_bar, can_be_int, get_date_time_string, \
    calc_elapsed_minutes, shroud, de_shroud, aes_crypt, aes_decrypt, read_json_file, confirm, confirm_yn, \
    write_json_file, ask_console, console_notice
from blacklite import Blacklite

"""xerxes.py: Shodan mass data collection system"""

__author__ = "Brandon Blackburn"
__maintainer__ = "Brandon Blackburn"
__email__ = "contact@bhax.net"
__website__ = "https://keybase.io/blackburnhax"
__copyright__ = "Copyright 2019, Brandon Blackburn"
__license__ = "Apache 2.0"

# Docstrings in this project should follow the reStructuredText system and will be in accordance with PEP-257
# For a primer on it's use visit: https://www.jetbrains.com/help/pycharm/using-docstrings-to-specify-types.html
# PEP-257: https://www.python.org/dev/peps/pep-0257/

if version_info<(3,6,0):
    raise RuntimeError("Python 3.6 or a more recent version is required. Detected Python %s.%s" % version_info[:2])

# pip install sshtunnel
# pip install pymongo
# pip install paramiko

# region TLS/SSL Self-signed certificate bypass
# TODO: Remove this TLS security bypass region
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# endregion

class Xerxes():
    def __init__(self):
        if (sys.version_info[0] < 3) or ((sys.version_info[0] == 3) and (sys.version_info[1] < 6)):
            raise Exception("Python 3.6 or a more recent version is required.")

        self.app_name="xerxes"
        # self.shodan_api_key = "00000000000000000000000000000000"
        # URL should end with trailing slash /
        self.shodan_url = "https://api.shodan.io/"
        self.xerxes_working_dir = get_working_dir(self.app_name)
        self.settings_standalone_file = "xerxes-settings.json"
        is_dir_writable(self.xerxes_working_dir)
        # TODO: remove main() from init and setup proper class for xerxes
        self.db = Blacklite(self.app_name)
        self.main()

    def validate_shodan_auth(self):
            self.settings_file = f"{self.xerxes_working_dir}/{self.settings_standalone_file}"
            settings_dict = read_json_file(self.settings_file)
            self.settings_dict['al_u'] = settings_dict.get('al_u', "-1")
            self.settings_dict['al_p'] = settings_dict.get('al_p', "-1")
            if self.settings_dict['al_u'] == "-1":
                entry = aes_crypt(de_shroud(self.pin), input("Enter your AlertLogic User Name (Double check first!): "))
                self.settings_dict['al_u'] = entry
                del entry

            if self.settings_dict['al_p'] == "-1":
                while True:
                    entry = getpass.getpass("Enter your AlertLogic Password: ")
                    if entry == getpass.getpass("Please re-enter AlertLogic Password to confirm: "):
                        entry = aes_crypt(de_shroud(self.pin), entry)
                        break
                    else:
                        print("Your passwords did not match, please try again.")

                self.settings_dict['al_p'] = entry
                del entry
            write_json_file(self.settings_file, self.settings_dict)


    # date_object = datetime.date.today() + relativedelta(months=-max_event_age_months)
    # max_event_age = datetime.datetime(date_object.year, date_object.month, date_object.day)
    # del date_object


    def filter_text(self, text, strict=False):
        import string
        # Get the difference of all ASCII characters from the set of printable characters
        nonprintable = set([chr(i) for i in range(128)]).difference(string.printable)
        # Use translate to remove all non-printable characters
        if not isinstance(text, str):
            return text

        filtered = text.translate({ord(character): None for character in nonprintable})
        if strict == True:
            filtered = filtered.replace('\n', ' ').replace('\r', '')
        return filtered


    def recursive_dict_scan(self, input_dict):
        for key, value in input_dict.items():
            if isinstance(value, dict):
                self.recursive_dict_scan(value)
            else:
                input_dict[key] = self.filter_text(value)
        return input_dict


    def recursive_list_scan(self, raw_list):
        if isinstance(raw_list, list):
            new_list = []
            for item in raw_list:
                new_list_item = self.filter_text(item)
                new_list.append(new_list_item)
            return new_list
        else:
            return raw_list


    def recursive_object_scan(self, raw_object):
        if isinstance(raw_object, dict):
            new = {}
            for key, value in raw_object.items():
                if isinstance(value, dict):
                    value = self.recursive_dict_scan(value)
                elif isinstance(value, str):
                    value = self.filter_text(value)
                elif isinstance(value, int):
                    pass
                elif isinstance(value, list):
                    value = self.recursive_list_scan(value)

                # Strict mode on the cleaner will remove any newlines or Carriage Returns
                key = self.filter_text(key, True)
                new[key] = value
            return new
        elif isinstance(raw_object, str):
            return raw_object
        elif isinstance(raw_object, int):
            return raw_object
        elif isinstance(self.value, list):
            return self.recursive_list_scan(self.value)
        else:
            return raw_object

    def shodan_api_query(self, endpoint, **kwargs):
        """
        Executes a properly formatted API call to the Shodan.io REST API with the supplied arguments.

        Designed with developers in mind. This method will print a fully formatted Slack message to the console if any HTTP errors occur (Outside of standard packet loss).

        This error text can then be directly copied into Slack for submission to support or other teams if needed.
        :param endpoint: The URL endpoint to hit on the API with NO LEADING OR PRECEEDING SLASHES. (e.g., GOOD: assets/search ,BAD: /assets/search  or  assets/search/)
        :type endpoint: str
        :keyword method: The type of HTTP command to execute. Currently accepts GET or POST
        :type method: str
        :keyword params: A dict containing the parameters to pass
        :type params: dict
        :keyword payload: A dict containing the query data to send
        :type params: dict
        :return: The users response. Yes = True, No = False
        :rtype: bool
        """
        headers = {"Content-Type": "application/json", 'Accept': 'application/json'}
        method = kwargs.get("method", "get")
        method = method.lower()

        parameters = kwargs.get("params", {})

        if not isinstance(parameters, dict):
            raise ValueError("params keyword passed to shodan_api_query is not a valid dict object")

        # We need "key" to be in the parameters to represent the authentication key, so add it if missing
        # In Py3, it's more performant to ask for forgiveness than permission. So Try/Except
        try:
            # Just testing if it
            parameters['key']
        except KeyError:
            parameters['key'] = self.shodan_api_key

        if len(parameters['key']) < 32:
            raise ValueError(f"Shodan api key appears malformed. First 4 chars of the key are: {kwargs['key'][:4]}")

        payload = kwargs.get("payload", "{}")

        while True:
            try:
                if method == "get":
                    response = requests.get(f"{self.shodan_url}{endpoint}", headers=headers, params=parameters,
                                            data=json.dumps(payload), verify=True)
                    break
                elif method == "post":
                    response = requests.post(f"{self.shodan_url}{endpoint}", headers=headers, params=parameters,
                                             data=json.dumps(payload), verify=True)
                    break
                else:
                    console_notice(f" Invalid Method passed to shodan_api_query:  {method}")
                    raise ValueError("Invalid Method passed to shodan_api_query:  {method}")

            except (
            requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                console_notice(" Packet loss when attempting to reach Shodan API")
        if not response.status_code == requests.codes.ok:
            print(f"\n\rShodan API returned an error *HTTP {response.status_code}- {http_status_code(response.status_code)}*\n\r*Request sent to endpoint:*\n\r```\n\r{endpoint}\n\r```\n\r\n\r*Payload sent:*\n\r```")
            pprint.pprint(payload, indent=4)
            print("```\n\r\n\r*Parameters passed:*\n\r```")
            pprint.pprint(parameters, indent=4)
            print("```\n\r\n\r*Server Response:*\n\r```")
            pprint.pprint(response.text, indent=4)
            print("\n\r```\n\r")
            if not confirm(prompt='Continue execution?', resp=True):
                raise ConnectionError(
                    "Shodan API returned an error HTTP {response.status_code}- {http_status_code(response.status_code)}")

        return response


    def shodan_info(self):

        response = self.shodan_api_query("api-info")
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(json.loads(response.text))
        print()

    def shodan_search(self, query, facets=""):
        if len(facets) < 1:
            parameters = {
                "query": query,
                "facets": facets
            }
            response = self.shodan_api_query("shodan/host/search", params=parameters )
        else:
            parameters = {
                "query": query
            }
            response = self.shodan_api_query("shodan/host/search", params=parameters)
        print(response.text)
        print()
        return response.text

    def main(self):
        print("Shodan Info:")
        self.shodan_info()
        print("Reading Shodan...")
        results = self.shodan_search("Org:google")
        json_results = json.loads(results)

        cleaned_json_results = self.recursive_object_scan(json_results)


        for discovered_host in cleaned_json_results['matches']:
            guid_set = False
            db_entry = {}
            for key, value in discovered_host.items():
                if key.lower() == "ip":
                    db_entry['guid'] = value
                    guid_set = True
                db_entry[key] = value
            self.db.write_recursive("shodan", **db_entry)


        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(cleaned_json_results)

        self.shodan_info()
        print("Complete")

if __name__ == "__main__":
    Xerxes()
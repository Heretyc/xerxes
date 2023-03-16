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

import csv
import getpass
import json
import math
import multiprocessing
import pprint
import re
import sqlite3
import time
from sys import version_info

import requests

from blacklite import Blacklite
# from multiprocessing import Pool, TimeoutError
from modblack2 import (aes_crypt, confirm, confirm_yn, console_notice, de_shroud, get_date_time_string, get_working_dir,
                       http_status_code, is_dir_writable, progress_bar, read_json_file, write_json_file)

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

# region TLS/SSL Self-signed certificate bypass
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
#
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# endregion

import urllib3
from packaging.version import Version

# Module version checking compliant with PEP 440 - https://www.python.org/dev/peps/pep-0440/
# For questions contact https://keybase.io/blackburnhax
if Version(urllib3.__version__) < Version("1.24.2"):
    raise ImportError("Attempted to import URLLib3 insecure version vulnerable to CVE-2019-11324")


class Xerxes:
    def __init__(self, query_string):
        if version_info < (3, 6, 0):
            raise RuntimeError(
                "Python 3.6 or a more recent version is required. Detected Python %s.%s" % version_info[:2]
            )
        # Set self.demo_mode to True and use Shodan paid query credits. Set to False and operate safely without fees
        self.demo_mode = False

        self.query_string = query_string

        self.app_name = "xerxes"
        self.max_parallelism = 10
        # self.shodan_api_key = "YOUR API KEY"
        # URL should end with trailing slash /
        self.shodan_url = "https://api.shodan.io/"
        self.xerxes_working_dir = get_working_dir(self.app_name)
        self.settings_standalone_file = "xerxes-settings.json"
        self.xerxes_output = f"{self.xerxes_working_dir}\\xerxes_data.json"
        self.xerxes_db = f"{self.xerxes_working_dir}\\xerxes.sqlite"
        self.xerxes_csv = f"{self.xerxes_working_dir}\\xerxes_{get_date_time_string()}.csv"
        is_dir_writable(self.xerxes_working_dir)
        # TODO: remove main() from init and setup proper class for xerxes
        self.db = Blacklite(self.app_name, False)
        self.total_pages = 0
        if self.query_string == "to_csv":
            self.to_csv()
        else:
            self.main()

    def validate_shodan_auth(self):
        self.settings_file = f"{self.xerxes_working_dir}/{self.settings_standalone_file}"
        settings_dict = read_json_file(self.settings_file)
        self.settings_dict["al_u"] = settings_dict.get("al_u", "-1")
        self.settings_dict["al_p"] = settings_dict.get("al_p", "-1")
        if self.settings_dict["al_u"] == "-1":
            entry = aes_crypt(de_shroud(self.pin), input("Enter your AlertLogic User Name (Double check first!): "))
            self.settings_dict["al_u"] = entry
            del entry

        if self.settings_dict["al_p"] == "-1":
            while True:
                entry = getpass.getpass("Enter your AlertLogic Password: ")
                if entry == getpass.getpass("Please re-enter AlertLogic Password to confirm: "):
                    entry = aes_crypt(de_shroud(self.pin), entry)
                    break
                else:
                    print("Your passwords did not match, please try again.")

            self.settings_dict["al_p"] = entry
            del entry
        write_json_file(self.settings_file, self.settings_dict)

    def write_json_file(self, json_file, dict_to_write):
        """
        Writes a dict to a JSON file in the filesystem, appends or modifies last_update key with EPOC time
        :param json_file: JSON File to write to
        :type json_file: str
        :param dict_to_write: dict to read information from that will be written into the json_file
        :type dict_to_write: dict
        :rtype: None
        """
        date = get_date_time_string()
        dict_to_write["last_update"] = date
        with open(json_file, "w") as f:
            json.dump(dict_to_write, f, ensure_ascii=False)

    def filter_text(self, text, strict=False):
        import string

        # Get the difference of all ASCII characters from the set of printable characters
        nonprintable = set([chr(i) for i in range(128)]).difference(string.printable)
        # Use translate to remove all non-printable characters
        if not isinstance(text, str):
            return text

        filtered = text.translate({ord(character): None for character in nonprintable})
        if strict == True:
            filtered = filtered.replace("\n", " ").replace("\r", "")
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
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        method = kwargs.get("method", "get")
        method = method.lower()

        parameters = kwargs.get("params", {})

        if not isinstance(parameters, dict):
            raise ValueError("params keyword passed to shodan_api_query is not a valid dict object")

        # We need "key" to be in the parameters to represent the authentication key, so add it if missing
        # In Py3, it's more performant to ask for forgiveness than permission. So Try/Except
        try:
            # Just testing if it
            parameters["key"]
        except KeyError:
            parameters["key"] = self.shodan_api_key

        if len(parameters["key"]) < 32:
            raise ValueError(f"Shodan api key appears malformed. First 4 chars of the key are: {kwargs['key'][:4]}")

        payload = kwargs.get("payload", "{}")

        while True:
            try:
                if method == "get":
                    response = requests.get(
                        f"{self.shodan_url}{endpoint}",
                        headers=headers,
                        params=parameters,
                        data=json.dumps(payload),
                        verify=True,
                    )
                    if response.status_code == 429:
                        # Rate limiter in Shodan, they want a max of 1 query per second
                        time.sleep(0.2)
                    else:
                        break
                elif method == "post":
                    response = requests.post(
                        f"{self.shodan_url}{endpoint}",
                        headers=headers,
                        params=parameters,
                        data=json.dumps(payload),
                        verify=True,
                    )
                    if response.status_code == 503:
                        # Rate limiter in Shodan, they want a max of 1 query per second
                        time.sleep(0.2)
                    else:
                        break
                else:
                    console_notice(f" Invalid Method passed to shodan_api_query:  {method}")
                    raise ValueError(f"Invalid Method passed to shodan_api_query:  {method}")

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectionError,
            ):
                console_notice(" Packet loss when attempting to reach Shodan API")
        if not response.status_code == requests.codes.ok:
            print(
                f"\n\rShodan API returned an error *HTTP {response.status_code}- {http_status_code(response.status_code)}*\n\r*Request sent to endpoint:*\n\r```\n\r{endpoint}\n\r```\n\r\n\r*Payload sent:*\n\r```"
            )
            pprint.pprint(payload, indent=4)
            print("```\n\r\n\r*Parameters passed:*\n\r```")
            pprint.pprint(parameters, indent=4)
            print("```\n\r\n\r*Server Response:*\n\r```")
            pprint.pprint(response.text, indent=4)
            print("\n\r```\n\r")
            if not confirm(prompt="Continue execution?", resp=True):
                raise ConnectionError(
                    f"Shodan API returned an error HTTP {response.status_code}- {http_status_code(response.status_code)}"
                )

        return response

    def shodan_info(self, pages_to_be_used=0):

        response = self.shodan_api_query("api-info")
        json_results = json.loads(response.text)
        cleaned_json_results = self.recursive_object_scan(json_results)
        credits_max = cleaned_json_results["usage_limits"]["query_credits"]
        credits_avail = cleaned_json_results["query_credits"]
        if pages_to_be_used > 0 and credits_max >= 0:
            if credits_avail > pages_to_be_used:
                print(f"This account has {credits_avail} Shodan Query credits remaining")
                print(f"The requested query will use {pages_to_be_used} and will not return all results.")
                print("Would you like to proceed with the Shodan query?")
                if confirm_yn():
                    print("Good luck!")
                    return True
                else:
                    raise ConnectionAbortedError("This Shodan account does not have enough query credits to finish.")
            else:
                console_notice(
                    f"This Shodan account will have {credits_avail-pages_to_be_used} query credits remaining after this run."
                )
                return True
        else:
            if credits_max == -1:
                # console_notice(f"Shodan link successful with UNLIMITED query credits.")
                pass
            else:
                console_notice(f"Shodan link successful with {credits_avail} of {credits_max} query credits.")
            return True

        # pp = pprint.PrettyPrinter(indent=4)
        # pp.pprint(json.loads(response.text))

    def shodan_search(self, query, facets="", page=1):
        # console_notice(f"SHODAN QUERY AGAINST PAGE {page}")
        if self.demo_mode:
            # Force only first page of results which Shodan does not charge query credits for
            page = 1
        if len(facets) < 1:
            parameters = {"query": query, "facets": facets, "page": page}
            response = self.shodan_api_query("shodan/host/search", params=parameters)
        else:
            parameters = {"query": query}
            response = self.shodan_api_query("shodan/host/search", params=parameters)
        # print(response.text)
        # print()
        return response.text

    def __last_resort_json_repair(self, s):
        """
        Trys a few ways to get a usable JSON object from the string given.
        Only use this as a actual last resort. Very Ugly.
        :param s: string to attempt to parse into JSON
        :type s: str
        :return: A JSON object, blank if no object could be made
        :rtype: object
        """
        attempts = 0
        max_attempts = 100
        while True:
            try:
                result = json.loads(s)  # try to parse...
                break  # parsing worked -> exit loop
            except Exception as e:
                # "Expecting , delimiter: line 34 column 54 (char 1158)"
                # position of unexpected character after '"'
                unexp = int(re.findall(r"\(char (\d+)\)", str(e))[0])
                # position of unescaped '"' before that
                unesc = s.rfind(r'"', 0, unexp)
                s = s[:unesc] + r"\"" + s[unesc + 1 :]
                # position of correspondig closing '"' (+2 for inserted '\')
                closg = s.find(r'"', unesc + 2)
                s = s[:closg] + r"\"" + s[closg + 1 :]
            attempts = attempts + 1
            if attempts > max_attempts:
                return json.loads("{}")  # Giving up and returning blank object
        return result

    def process_shodan_page(self, page_num):
        # Shodan starts pages at 1 rather than 0 for some reason. So we must raise our iterator accordingly
        page_num = page_num + 1

        console_notice(f"WORKER STARTING PAGE {page_num} of {self.total_pages}")
        processed_in_this_thread = 0

        def has_key(dict_object, key_to_check_for):
            try:
                test = dict_object[key_to_check_for]
                del test
                return True
            except KeyError:
                return False

        read_again = True
        attempts = 0
        attempts_max = 5
        while read_again:
            good_read = False
            try:
                results = self.shodan_search(self.query_string, "", page_num)
                good_read = True
            except ConnectionError:
                good_read = False

            if good_read:
                try:
                    json_results = json.loads(results)
                    read_again = False  # Good read first time. dont need to repeat
                except json.decoder.JSONDecodeError:
                    json_results = self.__last_resort_json_repair(results)
                    if len(json_results) < 10:  # Got bad JSON read, try again
                        read_again = True
            attempts = attempts + 1
            if attempts > attempts_max:
                read_again = False  # Too many attempts, give up!
                #  No good data for this page, master abort on this thread.
                console_notice(f"WORKER GAVE UP PARSING PAGE {page_num} of {self.total_pages}")
                return processed_in_this_thread

        cleaned_json_results = self.recursive_object_scan(json_results)

        for discovered_host in cleaned_json_results["matches"]:
            guid_set = False
            db_entry = {}
            if has_key(discovered_host, "ip_str"):
                db_entry["guid"] = discovered_host["ip_str"]
                if has_key(discovered_host, "product"):
                    db_entry["guid"] = f"{db_entry['guid']}_{discovered_host['product']}"
                    db_entry["product"] = discovered_host["product"]
                else:
                    db_entry["product"] = ""

                if has_key(discovered_host, "transport"):
                    db_entry["guid"] = f"{db_entry['guid']}_on_{discovered_host['transport']}"
                    db_entry["transport"] = discovered_host["transport"]
                else:
                    db_entry["transport"] = ""

                if has_key(discovered_host, "port"):
                    db_entry["guid"] = f"{db_entry['guid']}{discovered_host['port']}"
                    db_entry["port"] = discovered_host["port"]
                else:
                    db_entry["port"] = ""

                guid_set = True

            if has_key(discovered_host, "timestamp"):
                db_entry["updated"] = discovered_host["timestamp"]
            else:
                db_entry["updated"] = ""

            if has_key(discovered_host, "version"):
                db_entry["version"] = discovered_host["version"]
            else:
                db_entry["version"] = ""

            if has_key(discovered_host, "hostnames"):
                hostname_string = ""
                for item in discovered_host["hostnames"]:
                    if len(hostname_string) < 2:
                        hostname_string = f"{item}"
                    else:
                        hostname_string = f"{hostname_string}, {item}"
                db_entry["hostnames"] = hostname_string
            else:
                db_entry["hostnames"] = ""

            if has_key(discovered_host, "os"):
                db_entry["os"] = discovered_host["os"]
            else:
                db_entry["os"] = ""

            if has_key(discovered_host, "ip_str"):
                db_entry["ip"] = discovered_host["ip_str"]
            else:
                db_entry["ip"] = ""

            if has_key(discovered_host, "asn"):
                db_entry["asn"] = discovered_host["asn"]
            else:
                db_entry["asn"] = ""

            if has_key(discovered_host, "org"):
                db_entry["org"] = discovered_host["org"]
            else:
                db_entry["org"] = ""

            if has_key(discovered_host, "isp"):
                db_entry["isp"] = discovered_host["isp"]
            else:
                db_entry["isp"] = ""

            if has_key(discovered_host, "http"):
                http_dict = discovered_host["http"]

                if has_key(http_dict, "components"):
                    components_dict = http_dict["components"]
                    for key, value in components_dict.items():
                        db_entry[f"HAS{key}"] = "1"

            processed_in_this_thread = processed_in_this_thread + 1

            # print(f"{db_entry['guid']}")

            try:
                self.db.write("shodan", **db_entry)
            except KeyError:
                console_notice(f"WORKER GAVE UP WRITING TO DB on page {page_num} of {self.total_pages}")
                return processed_in_this_thread
        return processed_in_this_thread

    def key_reader_by_page(self, page_num):
        thread_results_list = []
        # Shodan starts pages at 1 rather than 0 for some reason. So we must raise our iterator accordingly
        page_num = page_num + 1

        console_notice(f"WORKER STARTING PAGE {page_num}")
        processed_in_this_thread = 0

        def has_key(dict_object, key_to_check_for):
            try:
                test = dict_object[key_to_check_for]
                del test
                return True
            except KeyError:
                return False

        results = self.shodan_search(self.query_string, "", page_num)
        json_results = json.loads(results)

        cleaned_json_results = self.recursive_object_scan(json_results)

        for discovered_host in cleaned_json_results["matches"]:
            guid_set = False
            db_entry = {}
            if has_key(discovered_host, "ip_str"):
                db_entry["guid"] = discovered_host["ip_str"]
                if has_key(discovered_host, "product"):
                    db_entry["guid"] = f"{db_entry['guid']}_{discovered_host['product']}"
                    db_entry["product"] = discovered_host["product"]
                else:
                    db_entry["product"] = ""

                if has_key(discovered_host, "transport"):
                    db_entry["guid"] = f"{db_entry['guid']}_on_{discovered_host['transport']}"
                    db_entry["transport"] = discovered_host["transport"]
                else:
                    db_entry["transport"] = ""

                if has_key(discovered_host, "port"):
                    db_entry["guid"] = f"{db_entry['guid']}{discovered_host['port']}"
                    db_entry["port"] = discovered_host["port"]
                else:
                    db_entry["port"] = ""

                guid_set = True

            if has_key(discovered_host, "timestamp"):
                db_entry["updated"] = discovered_host["timestamp"]
            else:
                db_entry["updated"] = ""

            if has_key(discovered_host, "version"):
                db_entry["version"] = discovered_host["version"]
            else:
                db_entry["version"] = ""

            if has_key(discovered_host, "hostnames"):
                hostname_string = ""
                for item in discovered_host["hostnames"]:
                    if len(hostname_string) < 2:
                        hostname_string = f"{item}"
                    else:
                        hostname_string = f"{hostname_string}, {item}"
                db_entry["hostnames"] = hostname_string
            else:
                db_entry["hostnames"] = ""

            if has_key(discovered_host, "os"):
                db_entry["os"] = discovered_host["os"]
            else:
                db_entry["os"] = ""

            if has_key(discovered_host, "ip_str"):
                db_entry["ip"] = discovered_host["ip_str"]
            else:
                db_entry["ip"] = ""

            if has_key(discovered_host, "asn"):
                db_entry["asn"] = discovered_host["asn"]
            else:
                db_entry["asn"] = ""

            if has_key(discovered_host, "org"):
                db_entry["org"] = discovered_host["org"]
            else:
                db_entry["org"] = ""

            if has_key(discovered_host, "isp"):
                db_entry["isp"] = discovered_host["isp"]
            else:
                db_entry["isp"] = ""

            if has_key(discovered_host, "http"):
                http_dict = discovered_host["http"]

                if has_key(http_dict, "components"):
                    components_dict = http_dict["components"]
                    for key, value in components_dict.items():
                        db_entry[f"HAS{key}"] = "1"

            processed_in_this_thread = processed_in_this_thread + 1

            print(f"{db_entry['guid']}")

            # hashed_db_entry = self.build_json_payload(db_entry)
            # try_again = True
            # while try_again:
            #     try:
            #         requests.post(self.xerxes_listener_api_url, json=hashed_db_entry, verify=False)
            #         try_again = False
            #     except requests.exceptions.ConnectionError:
            #         try_again = True
            # del try_again
            for key, value in db_entry.items():
                thread_results_list.append(key)
                # self.db.write("shodan", **db_entry)
        return thread_results_list

    def count_db(self):
        print("Indexing DB...")
        sqlite_connection = sqlite3.connect(self.xerxes_db)

        sqlite_connection.row_factory = sqlite3.Row
        db_read_cursor = sqlite_connection.execute(f"select * from shodan")
        count = 0
        row = db_read_cursor.fetchone()
        # Yes this is slow and clunky, but it is consistent and easy to debug.
        while row is not None:
            if count % 10000 == 0:
                print(f"Entries: {count}")
            count = count + 1
            row = db_read_cursor.fetchone()
        print(f"Entries: {count}")
        return count

    def to_csv(self):
        def dict_from_row(row):
            return dict(zip(row.keys(), row))

        if confirm("Dump SQLite database to CSV?", False):
            total_items = self.count_db()
            sqlite_connection = sqlite3.connect(self.xerxes_db)

            # db_read_cursor = sqlite_connection.cursor()
            sqlite_connection.row_factory = sqlite3.Row
            db_read_cursor = sqlite_connection.execute(f"select * from shodan")

            with open(self.xerxes_csv, "w", newline="") as file_object:
                row = db_read_cursor.fetchone()
                column_headers_list = row.keys()

                writer_for_dicts = csv.DictWriter(file_object, fieldnames=column_headers_list)
                writer_for_dicts.writeheader()
                processed_items = 0
                console_notice("Writing to CSV...")
                while row is not None:
                    processed_items = processed_items + 1
                    if processed_items % 1000 == 0:
                        progress_bar(processed_items, total_items, 25)
                    row_as_dict = dict_from_row(row)
                    writer_for_dicts.writerow(row_as_dict)
                    row = db_read_cursor.fetchone()
            console_notice(f"CSV written to {self.xerxes_csv}")
            return True

    def main(self):
        if self.demo_mode:
            console_notice("DEMO MODE IS ENABLED- Free Shodan use, but only first 100 results loaded!")
        # print("Reading Shodan...")

        # Initial read to determine number of pages
        results = self.shodan_search(self.query_string)
        json_results = json.loads(results)

        cleaned_json_results = self.recursive_object_scan(json_results)

        # Shodan processes 100 results per page
        self.total_pages = math.ceil(cleaned_json_results["total"] / 100)

        if self.demo_mode:
            # Force only first page of results which Shodan does not charge query credits for
            self.total_pages = 1

        self.shodan_info(self.total_pages)

        print(f"Total pages: {self.total_pages}")
        print(f"Total app entries: {cleaned_json_results['total']}")

        worker_returned_processed_count = 0

        # region Single-threaded operation mode
        # for page_num in range(0, self.total_pages):
        #     processed_count = self.process_shodan_page(page_num)
        #     worker_returned_processed_count = worker_returned_processed_count + processed_count
        # endregion Single-threaded operation mode

        # region Multi-threaded operation mode
        pool = multiprocessing.Pool(processes=self.max_parallelism)
        async_results = [
            pool.apply_async(self.process_shodan_page, args=(page_num,)) for page_num in range(0, self.total_pages)
        ]

        for result in async_results:
            worker_return = result.get()
            worker_returned_processed_count = worker_returned_processed_count + worker_return
        # endregion Multi-threaded operation mode

        print(f"{worker_returned_processed_count} host applications processed by workers.")
        print(f"{cleaned_json_results['total']} reported host application results by Shodan.")

        self.shodan_info()
        print("Shodan data retrieval Complete")
        # self.to_csv()
        print("All processes complete")


if __name__ == "__main__":
    # Set daemon_mode to True for continuous operation, set to false to run once and stop
    daemon_mode = True
    queries = ["Org:google"]
    while True:
        iteration = 0
        for query in queries:
            console_notice(f"Starting on query {iteration} of {len(queries)} - {query} ")
            progress_bar(iteration, len(queries))
            try:
                Xerxes(query)
            except Exception as e:
                console_notice(f" Exception on query {query}: Error was: {str(e)}")
                print()
            progress_bar(iteration, len(queries))
            iteration = iteration + 1
        if daemon_mode:
            console_notice(f"ALL QUERIES COMPLETE! Total iterations{iteration}")
        else:
            console_notice("ALL QUERIES COMPLETE!")
            break

    Xerxes("to_csv")

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

import sys
from sys import version_info
import os
import errno
import tempfile
import re
import json
import time
import zlib
import base64
import cryptography
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


"""modblack2.py: Shared library used for Blackburn projects"""

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


def is_dir_writable(directory_to_check):
    """
    Used to robustly check if a directory is, in fact, writable. If it is not, this function raises an error.
    Does a basic permissions check, then actually writes a test file to confirm beyond a shadow of a doubt.
    :param directory_to_check: The Directory to
    :type directory_to_check:
    :return: Returns the result of the check, though a exception is raised if it is not writable.
    :rtype: bool
    """
    if os.access(directory_to_check, os.W_OK | os.X_OK):
        try:
            testfile = tempfile.TemporaryFile(dir=directory_to_check)
            testfile.close()
        except OSError as e:
            if e.errno == errno.EACCES:  # 13
                return False
            e.filename = directory_to_check
            raise
            print("The Dir should be writable")
        return True
    else:
        raise Exception(f"Directory \"{directory_to_check}\" is not writeable.")
        # Getting to the actual return statement shouldnt be possible given the raise statement above, but just in case
        return False


def get_working_dir(app_name):
    """
    Used before any local file system write operation to find the proper directory to save everything depending on OS.
    Creates the directory as needed and verifies we have read/write.
    :return: Returns a string with the directory (has no trailing slash)
    :rtype: str
    """
    if sys.platform.startswith('freebsd'):
        home = os.path.expanduser("~")
        working_dir = os.path.abspath(f"{home}/.{app_name}")
        # Check if the directory exists, if not, make it. If the directory magically appears in between in the check
        # and the actual directory creation, catch that and continue working.
        # However, if any other errors are encountered, like a permissions issue, then abort and alert the user.
        if not os.path.isdir(working_dir):
            try:
                os.makedirs(working_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
        # The directory was created or already exists, now verify we have full permissions to it.
        if not is_dir_writable(working_dir):
            # This next raise statement should be redundant given that is_dir_writable() will raise an error if it fails
            # but, just to be safe we raise an error here too if isint writable.
            raise Exception(f"Directory \"{working_dir}\" is not writeable.")
        return working_dir
    elif sys.platform.startswith('linux'):
        home = os.path.expanduser("~")
        working_dir = os.path.abspath(f"{home}/.{app_name}")
        # Check if the directory exists, if not, make it. If the directory magically appears in between in the check
        # and the actual directory creation, catch that and continue working.
        # However, if any other errors are encountered, like a permissions issue, then abort and alert the user.
        if not os.path.isdir(working_dir):
            try:
                os.makedirs(working_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
        # The directory was created or already exists, now verify we have full permissions to it.
        if not is_dir_writable(working_dir):
            # This next raise statement should be redundant given that is_dir_writable() will raise an error if it fails
            # but, just to be safe we raise an error here too if isint writable.
            raise Exception(f"Directory \"{working_dir}\" is not writeable.")
        return working_dir
    elif sys.platform.startswith('darwin'):
        home = os.path.expanduser("~")
        working_dir = os.path.abspath(f"{home}/.{app_name}")
        # Check if the directory exists, if not, make it. If the directory magically appears in between in the check
        # and the actual directory creation, catch that and continue working.
        # However, if any other errors are encountered, like a permissions issue, then abort and alert the user.
        if not os.path.isdir(working_dir):
            try:
                os.makedirs(working_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
        # The directory was created or already exists, now verify we have full permissions to it.
        if not is_dir_writable(working_dir):
            # This next raise statement should be redundant given that is_dir_writable() will raise an error if it fails
            # but, just to be safe we raise an error here too if isint writable.
            raise Exception(f"Directory \"{working_dir}\" is not writeable.")
        return working_dir
    elif sys.platform.startswith('win'):
        appdata = os.getenv('APPDATA')
        working_dir = f"{appdata}\\{app_name}"
        # Check if the directory exists, if not, make it. If the directory magically appears in between in the check
        # and the actual directory creation, catch that and continue working.
        # However, if any other errors are encountered, like a permissions issue, then abort and alert the user.
        if not os.path.exists(working_dir):
            try:
                os.makedirs(working_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
        # The directory was created or already exists, now verify we have full permissions to it.
        if not is_dir_writable(working_dir):
            # This next raise statement should be redundant given that is_dir_writable() will raise an error if it fails
            # but, just to be safe we raise an error here too if isint writable.
            raise Exception(f"Directory \"{working_dir}\" is not writeable.")
        return working_dir
    # We haven't returned yet, meaning the OS were running on isint accounted for. Better stop a notify user about this.
    os_plat = sys.platform
    raise Exception(f"OS platform \"{os_plat}\" is not a supported OS.")


def get_time_string():
    """
    Pulls a human readable time of day string.
    Designed to standardize time storage and display for ease of use and consistency
    :return: Current system time in HH:MM:SS
    :rtype: str
    """
    now = datetime.datetime.now()
    return now.strftime("%H:%M:%S")


def console_notice(notice_text):
    """
    Quickly prints time stamped notices to the console. Often used for error messages or logging.
    :param notice_text: The text will be displayed on the users console
    :return: no returns
    :rtype: none
    """
    print(f"\n\r{get_time_string()}- {notice_text}")


def get_date_time_string(no_hours_mins=False):
    """
    Returns the current date/time string formatted for easy sorting in file systems
    Year-Month-Day-24 Hr-Minute-Second-offset
    Designed to standardize time storage and display for ease of use and consistency
    :param no_hours_mins: Returns only the Y-M-D - No Hours/Mins or offset
    :type no_hours_mins: bool
    :return: A string with a easily sortable date/time format
    :rtype: str
    """
    if no_hours_mins:
        return time.strftime("%Y-%m-%d")
    else:
        return time.strftime("%Y-%m-%d_%H-%M-%S_UTC%z")


def progress_bar(iteration, total, bar_length=50):
    """
    Creates a nice looking progress bar on the console
    :param iteration: Current location within a loop
    :type iteration: int
    :param total: Final location to reach within a loop
    :type total: int
    :param bar_length: Length in characters for the bar
    :type bar_length: int
    :return: All output is written to the current session console
    :rtype: None
    """
    try:
        percent = int(round((iteration / total) * 100))
        nb_bar_fill = int(round((bar_length * percent) / 100))
        bar_fill = '█' * nb_bar_fill
        bar_empty = ' ' * (bar_length - nb_bar_fill)
        sys.stdout.write("\r  [{0}] {1}%".format(str(bar_fill + bar_empty), percent))
        sys.stdout.flush()
    except ZeroDivisionError:
        pass


def calc_elapsed_minutes(past, present):
    """
    get past and present values using time.time() function

    ex: exec_time_minutes = calc_elapsed_minutes(time_start, time_stop)[0]
    Be sure to add the [0] parameter to round the result.

    :param past: Any earlier time.time()
    :type past: time.time
    :param present: Any latter time.time()
    :type present: time.time
    :return: A tuple of the minutes between the two. See above notes on rounding the result.
    :rtype: tuple
    """
    #
    past = int(past)
    present = int(present)
    d = divmod(present - past, 86400)  # days
    h = divmod(d[1], 3600)  # hours
    m = divmod(h[1], 60)  # minutes
    return m


def http_status_code(code):
    """
    Contains a database of all known HTTP status codes and thier corresponding plain text description.
    For use in both program output as well as parsing for specific issue types.
    :param code: A number containing the status code to lookup
    :type code: int
    :return: Returns a description of the status code.
    :rtype: str
    """
    selector = {
        200: "OK",
        201: "OK: Created",
        202: "OK: Accepted",
        203: "OK: Non-Authoritative Information",
        204: "OK: No Content",
        205: "OK: Reset Content",
        206: "OK: Partial Content",
        207: "OK: Multi-Status",
        208: "OK: Already Reported",
        226: "OK: IM Used",
        300: "Redirected: Multiple Choices",
        301: "Redirected: Moved Permanently",
        302: "Redirected: Found",
        303: "Redirected: See Other",
        304: "Redirected: Not Modified",
        305: "Redirected: Use Proxy",
        306: "Redirected: Switch Proxy",
        307: "Redirected: Temporary Redirect",
        308: "Redirected: Permanent Redirect",
        400: "Client Error: Bad Request",
        401: "Client Error: Unauthorized",
        402: "Client Error: Payment Required",
        403: "Client Error: Forbidden",
        404: "Client Error: Not Found",
        405: "Client Error: Method Not Allowed",
        406: "Client Error: Not Acceptable",
        407: "Client Error: Proxy Authentication Required",
        408: "Client Error: Request Timeout",
        409: "Client Error: Conflict",
        410: "Client Error: Gone",
        411: "Client Error: Length Required",
        412: "Client Error: Precondition Failled",
        413: "Client Error: Payload Too Large",
        414: "Client Error: URI Too Large",
        415: "Client Error: Unsupported Media Type",
        416: "Client Error: Range Not Satisfiable",
        417: "Client Error: Expectation Failed",
        418: "Client Error: I'm a teapot",
        421: "Client Error: Misdirected Request",
        422: "Client Error: Unprocessable Entity",
        423: "Client Error: Locked",
        424: "Client Error: Failed Dependency",
        426: "Client Error: Upgrade Required",
        428: "Client Error: Precondition Required",
        429: "Client Error: Too Many Requests",
        431: "Client Error: Request Header Fields Too Large",
        440: "Client Error: Login Time-Out",
        444: "Client Error: No Response",
        449: "Client Error: Retry With",
        451: "Client Error: Unavailable For Legal Reasons",
        495: "Client Error: SSL Certificate Error",
        496: "Client Error: SSL Certificate Requirted",
        497: "Client Error: HTTP Request Sent to HTTPS Port",
        499: "Client Error: Client Closed Request",
        500: "Server Error: Internal Server Error",
        501: "Server Error: Not Implemented",
        502: "Server Error: Bad Gateway",
        503: "Server Error: Service Unavailable",
        504: "Server Error: Gateway Timeout",
        505: "Server Error: HTTP Version Not Supported",
        507: "Server Error: Insufficient Storage",
        508: "Server Error: Loop Detected",
        510: "Server Error: Not Extended",
        511: "Server Error: Network Authentication Required",
        520: "Server Error: Unknown Error when connecting to server behind load balancer",
        521: "Server Error: Web Server behind load balancer is down",
        522: "Server Error: Connection Timed Out to server behind load balancer",
        523: "Server Error: Server behind load balancer is unreachable",
        524: "Server Error: TCP handshake with server behind load balancer completed but timed out",
        525: "Server Error: Load balancer could not negotiate a SSL/TLS handshake with server behind load balancer",
        526: "Server Error: Server behind load balancer returned invalid SSL/TLS cert to load balancer",
        527: "Server Error: Load balancer request timed out/failed after WAN connection was established to origin server"
    }
    return selector.get(code, "NA")


def ask_console(question_text, options_list):
    """
    Interactively prompts the user on the console to select one of multiple options. Useful for menus and branching selection trees.
    :param question_text: The text presented to the user
    :type question_text: str
    :param options_list: The possible selections the user can make
    :type options_list: list
    :return: The full text of the list item chosen (Respects case sensitivity)
    :rtype: str
    """
    while True:
        print("")
        print(question_text)
        available_choices = []
        for option in options_list:
            if option[0].lower() in available_choices:
                raise ReferenceError(
                    f"More than one option exists for \"{option[0].lower()}\", leading char must be unique."
                )
            else:
                print(f"[{option[0].lower()}] {option}")
                available_choices.append(option[0].lower())
        user_input = input("Please make a selection:")
        user_input = user_input.strip()
        if user_input[0].lower() in available_choices:
            break
        else:
            print(
                "Your entry was not understood. Please select an option using the characters in [brackets]"
            )
    for option in options_list:
        if option[0].lower() == user_input[0].lower():
            return option
    raise ReferenceError(
        "Menu option wasn't found for some reason, please debug.")


def confirm(prompt=None, resp=False):
    """
    Interactively prompts the user on the console to answer yes or no to a question.

    >>> confirm(prompt='Create Directory?', resp=True)
    Create Directory? [y]|n:
    True
    >>> confirm(prompt='Create Directory?', resp=False)
    Create Directory? [n]|y:
    False
    >>> confirm(prompt='Create Directory?', resp=False)
    Create Directory? [n]|y: y
    True
    :param prompt: The question text presented to the user
    :type prompt: str
    :param resp: The default response if the user simply hits ENTER without providing a Yes or No
    :type resp: bool
    :return: The users response. Yes = True, No = False
    :rtype: bool
    """

    if prompt is None:
        prompt = 'Confirm'

    if resp:
        prompt = '%s [%s]|%s: ' % (prompt, 'y', 'n')
    else:
        prompt = '%s [%s]|%s: ' % (prompt, 'n', 'y')
    try:
        while True:
            ans = input(prompt)
            if not ans:
                return resp
            if ans not in ['y', 'Y', 'n', 'N']:
                print('please enter y or n.')
                continue
            if ans == 'y' or ans == 'Y':
                return True
            if ans == 'n' or ans == 'N':
                return False
    except EOFError:
        print(f"Unable to prompt on console, assuming {resp}.")


def confirm_yn(default_resp=False):
    """
    Simply asks the user to respond yes or no. The question should be printed beforehand
    If needed, provide a default response if the confirmation dialog fails to show (multi-threaded).
    :param default_resp: What to default to if the prompt cant display
    :type default_resp: bool
    :return:
    """
    try:
        while True:
            user_input = input("Please confirm [y,n]: ")
            user_input = user_input.strip()
            user_input = user_input.lower()
            if user_input == "y" or user_input == "yes":
                return True
            elif user_input == "n" or user_input == "no":
                return False
            else:
                print(" ")
                print("Please enter a yes or no.")
    except EOFError:
        print(f"Unable to prompt on console, assuming {default_resp}.")
        return default_resp


def can_be_int(string_to_check):
    try:
        int(string_to_check)
        return True
    except ValueError:
        return False


def extract_cve(text):
    """
    Performs a regular expression match on a string to determine if a MITRE Common Vulnerabilities and Exposures entry (CVE) exists. If one does, the formatted CVE is returned. If not, a zero length string is returned.

    Respects the expanded CVE definition with four or more digits in the sequence number portion of the ID (e.g., CVE-1999-0067, CVE-2014-12345, CVE-2016-7654321).
    :param text: The text which will be searched for a CVE
    :type text: str
    :return: The full properly formatted text of the CVE ID, or a zero length string.
    :rtype: str
    """
    try:
        cve_found = re.search('(CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,}))', text, re.IGNORECASE).group(1)
        cve_found = cve_found.upper()
    except AttributeError:
        cve_found = ""
    return cve_found


def aes_crypt(password, plaintext):
    salt = base64.b64encode(os.urandom(64)).decode('utf-8')
    salt_bytes = str.encode(salt)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(str.encode(password)))
    f = Fernet(key)
    cyphertext_bytes = f.encrypt(str.encode(plaintext))
    cyphertext = cyphertext_bytes.decode()
    full_return = f"{cyphertext}****{salt}"
    return full_return


def aes_decrypt(password, cyphertext_salt):
    cyphertext = ""
    salt = ""
    delimiter = "*"
    found_cyphertext_end = False
    delimiters_in_a_row = 0
    for character in cyphertext_salt:
        if character == delimiter:
            delimiters_in_a_row = delimiters_in_a_row + 1
        else:
            delimiters_in_a_row = 0
            if found_cyphertext_end:
                salt = f"{salt}{character}"
            else:
                cyphertext = f"{cyphertext}{character}"
        if delimiters_in_a_row > 3:
            found_cyphertext_end = True

    salt_bytes = str.encode(salt)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_bytes, iterations=100000, backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(str.encode(password)))
    f = Fernet(key)
    try:
        plaintext_bytes = f.decrypt(str.encode(cyphertext))
    except cryptography.fernet.InvalidToken:
        console_notice("Invalid password supplied")
        return False
    plaintext = plaintext_bytes.decode()
    return plaintext


def shroud(string):
    string_bytearray = str.encode(string)
    s_text = zlib.compress(string_bytearray, 1)
    return s_text


def de_shroud(s_text):
    string_bytearray = zlib.decompress(s_text)
    string_text = string_bytearray.decode()
    return string_text


def write_json_file(json_file, dict_to_write):
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
    with open(json_file, 'w') as f:
        json.dump(dict_to_write, f, ensure_ascii=False)


def read_json_file(json_file):
    """
    Reads a JSON formatted plain text file into a dict construct and returns the dict, if none exists, uses template
    :param json_file: JSON File to read from
    :type json_file: str
    :rtype: dict
    """
    date = get_date_time_string()
    new_file_template = {
        "last_update": date
    }
    while True:
        try:
            with open(json_file) as json_data:
                return json.load(json_data)
        except FileNotFoundError:
            print("State file does not exist, creating one with default settings...")
            with open(json_file, 'w') as f:
                json.dump(new_file_template, f, ensure_ascii=False)
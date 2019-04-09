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
import sqlite3
import time
import re
from collections import OrderedDict
from modblack2 import get_working_dir, is_dir_writable, can_be_int


"""blacklite.py: SQLite shared library used for Blackburn projects"""

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

class Blacklite():
    def __init__(self, app_name):
        self.app_name = app_name
        self.db_file = f"{get_working_dir(app_name)}/{self.app_name}.sqlite"


    def __alpha_num_sanitize(self, string_to_sanitize):
        """
        Takes any string input and only keeps A-Z a-z 0-9. Used for scrubbing strings against potential injection attacks.
         "This is a DROP test 1=1 for dropping bad commands." becomes "ThisisaDROPtest11fordroppingbadcommands"

        This is the more restrictive version of sql_sanitize, but can be used in conjunction with it to
        scrub a string of even more potentially malicious data
        "This is a DROP test 1=1 for dropping bad commands." becomes "Thisisatest11forpingbadcommands"
        :param string_to_sanitize: The string to be sanitized
        :type string_to_sanitize: str
        :return: Sanitized string
        :rtype: str
        """
        return ''.join(chr for chr in string_to_sanitize if chr.isalnum())


    def __sql_sanitize(self, string_to_sanitize):
        """
        Actively searches for SQL query statements that will delete or heavily modify data.
        "This is a DROP test 1=1 for dropping bad commands." becomes "This is a  test 1=1 for ping bad commands."

        This is the less restrictive version of self.__alpha_num_sanitize, but can be used in conjunction with it to
        scrub a string of even more potentially malicious data
        "This is a DROP test 1=1 for dropping bad commands." becomes "Thisisatest11forpingbadcommands"
        :param string_to_sanitize: String to sanitize
        :type string_to_sanitize: str
        :return: Returns string with all possible commands removed
        :rtype: str
        """
        blacklisted_terms = "drop|alter|add|create|delete|rollback|release|attach|detatch|join"
        regex_expression = re.compile(blacklisted_terms, re.IGNORECASE)
        string = regex_expression.sub("", string_to_sanitize)

        return string


    def __build_db_if_needed(self, table_name, **kwargs):
        """
        Used for validating that the DB exists and creates the supplied table and the DB if needed.
        Should be used prior to starting DB operations.
        :param table_name: Name of the table we should check for
        :type table_name: str
        :return: Nothing
        :rtype: None
        """
        # region SQL Injection Protection

        # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
        # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
        sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_name))

        # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
        del table_name

        # endregion
        headings = []
        for key, value in kwargs.items():
            sanitized_heading = self.__alpha_num_sanitize(key)
            # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
            del key

            if sanitized_heading.lower() == "guid" or sanitized_heading.lower() == "date":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()

            headings.append(sanitized_heading)

        # Using OrderedDict to instantly create a deduped list, then typecasting it back to as list for comparison
        deduped_headings = list(OrderedDict.fromkeys(headings))
        if len(deduped_headings) != len(headings):
            raise ValueError("A field keyword was duplicated after sanitization. Please Debug.")

        # Memory space cleanup, we use deduped_headings going forward
        del headings

        # Find reserved keywords and reorder list as needed
        order = []
        # We have 2 reserved keywords (guid and date) so start normal indexes at 2, like a reserved IP block in DHCP
        list_index = 2
        guid_found = False
        date_found = False
        for heading in deduped_headings:
            if heading == "guid":
                # Fixed list index 0
                order.append(0)
                guid_found = True
            elif heading == "date":
                # Fixed list index 1
                order.append(1)
                date_found = True
            else:
                order.append(list_index)
                # Only increment if we use a standard list_index
                list_index = list_index + 1

        # date is added if not found in the given headings, since we will simply use epoc time if none is given
        if not date_found:
            # Fixed list index 1
            order.append(1)
            deduped_headings.append("date")

        if not guid_found:
            raise ValueError("guid is a required keyword and was not found after sanitization and dedupe. Please Debug.")

        # Rebuild the headings with designated orderings, then delete the old list to keep memory space clean
        re_ordered_headings = [deduped_headings[item] for item in order]
        del deduped_headings
        del order

        # Finally build the finished query needed to create the table
        # It will look similar to this example, including guid, date, and each heading with a TEXT SQL typecast
        # query = f"CREATE TABLE IF NOT EXISTS {sanitized_table_name} (guid INTEGER PRIMARY KEY, date TEXT, hostname TEXT, ip TEXT, mac TEXT)"
        #guid INTEGER PRIMARY KEY, date TEXT, hostname TEXT, ip TEXT, mac TEXT)
        query = f"CREATE TABLE IF NOT EXISTS `{sanitized_table_name}` ("
        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        for heading in re_ordered_headings:
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "

            if heading == "guid":
                typecast = "INTEGER PRIMARY KEY"
            elif heading == "date":
                # Dont need this, but if for some reason the type needs to be changed for a specific item, this is how
                typecast = "TEXT"
            else:
                typecast = "TEXT"
            query = f"{query}`{heading}` {typecast}"
        # Add the closing parenthesis to the query
        query = f"{query})"

        # Minimizing cycles with DB open in memory front-load all operations, then get in, get out
        sqlite_connection = sqlite3.connect(self.db_file)
        with sqlite_connection:
            db_create_cursor = sqlite_connection.cursor()
            db_create_cursor.execute(query)
            sqlite_connection.commit()
        return None


    def __find_entries_in_db(self, table_name, transaction_id=None, date=None, cid=None, hostname=None, ips=None, macs=None, **kwargs):
        """
        Locates any matching entries based on exactly one search parameter, given in the keyword args.
        :param table_name: Table name to search in
        :type table_name: str
        :param transaction_id: primary key value for row (it is always globally unique)
        :type transaction_id: int
        :param date: Epoc date format to search. Use time() to construct specific times/dates
        :type date: int
        :param cid: Customer ID number
        :type cid: str
        :param hostname: device domain name (preferably FQDN where possible)
        :type hostname: str
        :param ips: any of the IPs associated with an asset
        :type ips: str
        :param macs: any of the MAC addresses associated with an asset
        :type macs: str
        :param kwargs:
        :type kwargs:
        :return: Returns a tuple of tuples containing the search results
        :rtype: tuple
        """
        # region Confirming that we only received 2 arguments to this function
        # TODO: Refactor DB Names
        args_in_use = 0
        if not transaction_id is None:
            args_in_use += 1
        if not date is None:
            args_in_use += 1
        if not cid is None:
            args_in_use += 1
        if not hostname is None:
            args_in_use += 1
        if not ips is None:
            args_in_use += 1
        if not macs is None:
            args_in_use += 1
        if args_in_use > 1:
            raise Exception(f"Function supports exactly 2 arguments, {args_in_use + 1} were supplied.")
        if args_in_use == 0:
            raise Exception(f"Function supports exactly 2 arguments, only 1 was supplied.")
        # endregion

        self.__build_db_if_needed(table_name)

        sqlite_connection = sqlite3.connect(self.db_file)

        with sqlite_connection:
            db_read_cursor = sqlite_connection.cursor()

            # region SQL Injection Protection

            # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
            # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
            sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_name))

            # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
            del table_name

            # endregion

            query = f'''CREATE TABLE if not exists {sanitized_table_name} (
                                       transaction_id integer PRIMARY KEY,
                                       date text,
                                       cid text,
                                       hostname text,
                                       ips text,
                                       macs text
                                       )'''
            db_read_cursor.execute(query)

            query = "None Supplied"
            parameter = "None Supplied"

            # region Building query strings
            # We are individually specifying each field query here to further reduce the chance of abuse/accidents
            if transaction_id is not None:
                # region SQL Injection protection
                # we are taking transaction_id, converting it to a string for scrubbing, then going back to an int
                sanitized_transaction_id = int(self.__sql_sanitize(self.__alpha_num_sanitize(str(transaction_id))))
                # and also delete the unsafe variable
                del transaction_id
                # endregion
                query = f"SELECT * FROM {sanitized_table_name} WHERE transaction_id LIKE ?"
                parameter = (f"%{sanitized_transaction_id}%",)

            if date is not None:
                # region SQL Injection protection
                # we are taking transaction_id, converting it to a string for scrubbing, then going back to an int
                sanitized_date = self.__sql_sanitize(str(date))
                # and also delete the unsafe variable
                del date
                # endregion
                query = f"SELECT * FROM {sanitized_table_name} WHERE date LIKE ?"
                parameter = (f"%{sanitized_date}%",)

            if cid is not None:
                # region SQL Injection protection
                # we are taking transaction_id, converting it to a string for scrubbing, then going back to an int
                sanitized_cid = self.__sql_sanitize(self.__alpha_num_sanitize(str(cid)))
                # and also delete the unsafe variable
                del cid
                # endregion
                query = f"SELECT * FROM {sanitized_table_name} WHERE cid LIKE ?"
                parameter = (f"%{sanitized_cid}%",)

            if hostname is not None:
                # region SQL Injection protection
                # we are taking transaction_id, converting it to a string for scrubbing, then going back to an int
                sanitized_hostname = self.__sql_sanitize(str(hostname))
                # and also delete the unsafe variable
                del hostname
                # endregion
                query = f"SELECT * FROM {sanitized_table_name} WHERE hostname LIKE ?"
                parameter = (f"%{sanitized_hostname}%",)

            if ips is not None:
                query = f"SELECT * FROM {sanitized_table_name} WHERE ips LIKE ?"
                parameter = (f"%{ips}%",)

            if macs is not None:
                query = f"SELECT * FROM {sanitized_table_name} WHERE macs LIKE ?"
                parameter = (f"%{macs}%",)
            # endregion
            db_read_cursor.execute(query, parameter)
            rows = db_read_cursor.fetchall()


            # Intentionally not using the .commit() statement as this function is read-only and we shouldn't have
            # anything to commit, just to be safe.
            # sqlite_connection.commit()
        sqlite_connection.close()
        return rows


    def write_strict(self, table_name, **kwargs):
        """
        Writes a new entry to the DB, if a guid collision occurs, throws an exception.
        If any new column header keyword arguments are found, throws an exception.
        Date is automatically generated as time in sec since epoc as a floating point number
        :param table_name: The SQL table being referenced
        :param kwargs:
        :return:
        """
        date = time.time()


        self.__build_db_if_needed(table_name, **kwargs)

        # region SQL Injection Protection

        # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
        # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
        sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_name))

        # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
        del table_name

        # endregion

        # we are using parametrized values in the query to let the execute() command handle sql injection protection
        # query = f"INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
        # parameters = (date, guid, hostname, str(ip), str(mac))

        # Building: >>"INSERT INTO {sanitized_table_name} (<<date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
        query = f"INSERT INTO {sanitized_table_name} ("
        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        guid_found = False
        date_found = False
        values_list = []
        # Building header keywords section of the query first, while generating a list of the values to add next
        for key, value in kwargs.items():
            # Building: "INSERT INTO {sanitized_table_name} (>>date, guid, hostname, ip, mac<<) VALUES (?, ?, ?, ?, ?)"
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "

            sanitized_heading = self.__alpha_num_sanitize(key)
            # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
            del key


            # region Save the values to a separate list and check for reserved keywords
            # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
            if sanitized_heading.lower() == "guid":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()
                # and stored as raw integers in the DB
                values_list.append(value)
                guid_found = True
            elif sanitized_heading.lower() == "date":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()
                # and stored as raw integers in the DB
                values_list.append(value)
                date_found = True
            else:
                # Force value to string if it isn't the guid or date
                values_list.append(str(value))
            # endregion


            query = f"{query}{sanitized_heading}"


        # date is added if not found in the given headings, since we will simply use epoc time if none is given
        if not date_found:
            # Note: This string has a comma and space, but ends with nothing. This way it appears inline with above items
            query = f"{query}, date"
            values_list.append(date)

        if not guid_found:
            raise ValueError("guid is a required keyword and was not found after sanitization and dedupe. Please Debug.")

        # Add the closing parenthesis to the first part of the query, and start VALUES section
        # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac>>) VALUES (<<?, ?, ?, ?, ?)"
        query = f"{query}) VALUES ("

        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        for value in values_list:
            # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "
            query = f"{query}?"

        # Add the closing parenthesis to the last part of the query, finishing the values section
        # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?>>)<<"
        query = f"{query})"

        # Cast the values list into a tuple for SQL to read in properly
        parameters = tuple(values_list)


        # Minimizing cycles with DB open in memory front-load all operations, then get in, get out
        sqlite_connection = sqlite3.connect(self.db_file)
        with sqlite_connection:
            db_write_cursor = sqlite_connection.cursor()
            db_write_cursor.execute(query, parameters)
            sqlite_connection.commit()
        sqlite_connection.close()
        return None

    def write(self, table_name, **kwargs):
        """
        Writes a new entry to the DB, overwrites if a guid collision occurs
        If any new column header keyword arguments are found, they are appended silently to the schema.
        Date is automatically generated as time in sec since epoc as a floating point number
        :param table_name: The SQL table being referenced
        :param kwargs:
        :return:
        """

        date = time.time()


        self.__build_db_if_needed(table_name, **kwargs)

        # region SQL Injection Protection

        # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
        # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
        sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_name))

        # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
        del table_name

        # endregion

        # we are using parametrized values in the query to let the execute() command handle sql injection protection
        # query = f"INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
        # parameters = (date, guid, hostname, str(ip), str(mac))

        # Note: "INSERT OR REPLACE" gives this function the ability to overwrite existing matching guids
        # Building: >>"INSERT INTO {sanitized_table_name} (<<date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
        query = f"INSERT OR REPLACE INTO {sanitized_table_name} ("
        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        guid_found = False
        date_found = False
        values_list = []
        # Building header keywords section of the query first, while generating a list of the values to add next
        for key, value in kwargs.items():
            # Building: "INSERT INTO {sanitized_table_name} (>>date, guid, hostname, ip, mac<<) VALUES (?, ?, ?, ?, ?)"
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "

            sanitized_heading = self.__alpha_num_sanitize(key)
            # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
            del key


            # region Save the values to a separate list and check for reserved keywords
            # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
            if sanitized_heading.lower() == "guid":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()
                # and stored as raw integers in the DB
                if can_be_int(value):
                    value = int(value)
                else:
                    raise TypeError(f"guid given cannot be converted or used as an integer.  guid={value}")
                values_list.append(value)
                guid_found = True
            elif sanitized_heading.lower() == "date":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()
                # and stored as raw integers in the DB
                values_list.append(value)
                date_found = True
            else:
                # Force value to string if it isn't the guid or date
                values_list.append(str(value))
            # endregion


            query = f"{query}{sanitized_heading}"


        # date is added if not found in the given headings, since we will simply use epoc time if none is given
        if not date_found:
            # Note: This string has a comma and space, but ends with nothing. This way it appears inline with above items
            query = f"{query}, date"
            values_list.append(date)

        if not guid_found:
            raise ValueError("guid is a required keyword and was not found after sanitization and dedupe. Please Debug.")

        # Add the closing parenthesis to the first part of the query, and start VALUES section
        # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac>>) VALUES (<<?, ?, ?, ?, ?)"
        query = f"{query}) VALUES ("

        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        for value in values_list:
            # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "
            query = f"{query}?"

        # Add the closing parenthesis to the last part of the query, finishing the values section
        # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?>>)<<"
        query = f"{query})"

        # Cast the values list into a tuple for SQL to read in properly
        parameters = tuple(values_list)


        # Minimizing cycles with DB open in memory front-load all operations, then get in, get out, but...
        # we need to handle a few exception cases to automatically extend the database schema as needed
        sqlite_connection = sqlite3.connect(self.db_file)
        with sqlite_connection:
            db_write_cursor = sqlite_connection.cursor()
            try_again = True
            attempts = 0
            while try_again:
                try:
                    db_write_cursor.execute(query, parameters)
                    try_again = False
                except sqlite3.OperationalError as error_tuple:
                    error_text = str(error_tuple)
                    # Typical error: 'table table_name has no column named my_column'
                    # Breaking each word into separate list item to check and parse
                    error_wordlist = error_text.split(" ")
                    error_comparison_list = ["table", sanitized_table_name, "has", "no", "column", "named"]
                    error_converted_list = error_wordlist[0]

                    if error_comparison_list == error_wordlist[0:6]:
                        # print(f"Ok, make a new column in {sanitized_table_name} table called {error_wordlist[6]}")
                        schema_update_query = f"ALTER TABLE {sanitized_table_name} ADD COLUMN {error_wordlist[6]};"
                        db_write_cursor.execute(schema_update_query)
                        sqlite_connection.commit()
                        attempts = attempts + 1
                        if attempts >= 100:
                            raise KeyError(f"After {attempts} attempts, the schema still reports missing headings. Giving up!")
                    else:
                        raise KeyError(f"Unable to append schema. Original error was: sqlite3.OperationalError: {error_text}")
            sqlite_connection.commit()
        sqlite_connection.close()
        return None

    def __build_child_db_if_needed(self, child_table, parent_guid, parent_table, **kwargs):
            """
            Used for validating that the DB exists and creates the supplied table and the DB if needed.
            Should be used prior to starting DB operations.
            :param table_name: Name of the table we should check for
            :type table_name: str
            :return: Nothing
            :rtype: None
            """

            # region SQL Injection Protection

            # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
            # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
            sanitized_child_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(child_table))
            parent_table = self.__sql_sanitize(self.__alpha_num_sanitize(parent_table))
            # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
            del child_table

            # endregion
            headings = []
            for key, value in kwargs.items():
                sanitized_heading = self.__alpha_num_sanitize(key)
                # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
                del key

                if sanitized_heading.lower() == "date":
                    # Reserved keywords are forced lowercase every time
                    sanitized_heading = sanitized_heading.lower()

                headings.append(sanitized_heading)

            # Using OrderedDict to instantly create a deduped list, then typecasting it back to as list for comparison
            deduped_headings = list(OrderedDict.fromkeys(headings))
            # TODO: Remove sanitization bypass
            deduped_headings = headings

            if len(deduped_headings) != len(headings):
                # TODO: Remove sanitization bypass
                # raise ValueError("A field keyword was duplicated after sanitization. Please Debug.")
                print(f"A field keyword was duplicated after sanitization. Please Debug. child_table={child_table}")

            # Memory space cleanup, we use deduped_headings going forward
            # TODO: Remove sanitization bypass
            # del headings

            # note: We have no reserved keywords in this scope, unlike outer scopes, skipping reorder


            # Finally build the finished query needed to create the table
            # It will look similar to this example, including guid, date, and each heading with a TEXT SQL typecast
            # query = f"CREATE TABLE IF NOT EXISTS {sanitized_child_table_name} (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, hostname TEXT, ip TEXT, mac TEXT)"

            query = f"CREATE TABLE IF NOT EXISTS {sanitized_child_table_name} ( id_{sanitized_child_table_name} INTEGER PRIMARY KEY AUTOINCREMENT, "
            # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
            first_element = True
            for heading in deduped_headings:
                if first_element:
                    first_element = False
                else:
                    # This way we don't need to remove a trailing comma and space in the query after loop completion
                    query = f"{query}, "

                typecast = "TEXT"
                query = f"{query}{heading} {typecast}"


            # this is the specified column for storing the parent foreign key id which links the tables
            # typecast must be identical to parent guid key type

            typecast = "INTEGER NOT NULL"
            query = f"{query}, parent_guid {typecast}, FOREIGN KEY (parent_guid) REFERENCES `{parent_table}` ON UPDATE CASCADE ON DELETE CASCADE"

            # Add the closing parenthesis to the query
            query = f"{query})"

            # Minimizing cycles with DB open in memory front-load all operations, then get in, get out
            sqlite_connection = sqlite3.connect(self.db_file)
            with sqlite_connection:
                db_create_cursor = sqlite_connection.cursor()
                db_create_cursor.execute(query)
                sqlite_connection.commit()
            return None


    def __write_child(self, child_table, parent_guid_value, parent_table, **kwargs):
            """
            Writes a new entry to the DB, overwrites if a guid collision occurs
            If any new column header keyword arguments are found, they are appended silently to the schema.
            Date is automatically generated as time in sec since epoc as a floating point number
            :param table_name: The SQL table being referenced
            :param kwargs:
            :return:
            """

            date = time.time()

            self.__build_child_db_if_needed(child_table, parent_guid_value, parent_table, **kwargs)

            # region SQL Injection Protection

            # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
            # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
            sanitized_child_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(child_table))
            parent_table = self.__sql_sanitize(self.__alpha_num_sanitize(parent_table))
            # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
            del child_table

            # endregion

            # we are using parametrized values in the query to let the execute() command handle sql injection protection
            # query = f"INSERT INTO {sanitized_child_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
            # parameters = (date, guid, hostname, str(ip), str(mac))

            # Note: "INSERT OR REPLACE" gives this function the ability to overwrite existing matching guids
            # Building: >>"INSERT INTO {sanitized_child_table_name} (<<date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
            query = f"INSERT OR REPLACE INTO {sanitized_child_table_name} ("
            # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
            first_element = True
            values_list = []
            # Building header keywords section of the query first, while generating a list of the values to add next
            for key, value in kwargs.items():
                # Building: "INSERT INTO {sanitized_child_table_name} (>>date, guid, hostname, ip, mac<<) VALUES (?, ?, ?, ?, ?)"
                if first_element:
                    first_element = False
                else:
                    # This way we don't need to remove a trailing comma and space in the query after loop completion
                    query = f"{query}, "

                sanitized_heading = self.__alpha_num_sanitize(key)
                # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
                del key

                # region Save the values to a separate list and check for reserved keywords
                # Building: "INSERT INTO {sanitized_child_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
                if sanitized_heading.lower() == "guid":
                    raise TypeError(f"A column is labeled 'guid', this should be passed as a parameter instead")
                elif sanitized_heading.lower() == "date":
                    # Reserved keywords are forced lowercase every time
                    sanitized_heading = sanitized_heading.lower()
                    # and stored as raw integers in the DB
                    values_list.append(value)
                    date_found = True
                else:
                    # Force value to string if it isn't the guid or date
                    values_list.append(str(value))
                # endregion

                query = f"{query}{sanitized_heading}"


            # store parent guid as paremeter and update query
            if can_be_int(parent_guid_value):
                # Force it to an int type
                parent_guid_value = int(parent_guid_value)
            else:
                raise TypeError(f"guid given cannot be converted or used as an integer.  guid={parent_guid_value}")
            values_list.append(parent_guid_value)
            query = f"{query}, parent_guid"

            # Add the closing parenthesis to the first part of the query, and start VALUES section
            # Building: "INSERT INTO {sanitized_child_table_name} (date, guid, hostname, ip, mac>>) VALUES (<<?, ?, ?, ?, ?)"
            query = f"{query}) VALUES ("

            # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
            first_element = True
            for value in values_list:
                # Building: "INSERT INTO {sanitized_child_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
                if first_element:
                    first_element = False
                else:
                    # This way we don't need to remove a trailing comma and space in the query after loop completion
                    query = f"{query}, "
                query = f"{query}?"




            # Add the closing parenthesis to the last part of the query, finishing the values section
            # Building: "INSERT INTO {sanitized_child_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?>>)<<"
            query = f"{query})"

            # Cast the values list into a tuple for SQL to read in properly
            parameters = tuple(values_list)

            # Minimizing cycles with DB open in memory front-load all operations, then get in, get out, but...
            # we need to handle a few exception cases to automatically extend the database schema as needed
            sqlite_connection = sqlite3.connect(self.db_file)
            with sqlite_connection:
                db_write_cursor = sqlite_connection.cursor()
                try_again = True
                attempts = 0
                while try_again:
                    try:
                        db_write_cursor.execute(query, parameters)
                        try_again = False
                    except sqlite3.OperationalError as error_tuple:
                        error_text = str(error_tuple)
                        # Typical error: 'table table_name has no column named my_column'
                        # Breaking each word into separate list item to check and parse
                        error_wordlist = error_text.split(" ")
                        error_comparison_list = ["table", sanitized_child_table_name, "has", "no", "column", "named"]
                        error_converted_list = error_wordlist[0]

                        if error_comparison_list == error_wordlist[0:6]:
                            # print(f"Ok, make a new column in {sanitized_child_table_name} table called {error_wordlist[6]}")
                            schema_update_query = f"ALTER TABLE {sanitized_child_table_name} ADD COLUMN {error_wordlist[6]};"
                            db_write_cursor.execute(schema_update_query)
                            sqlite_connection.commit()
                            attempts = attempts + 1
                            if attempts >= 100:
                                raise KeyError(
                                    f"After {attempts} attempts, the schema still reports missing headings. Giving up!")
                        else:
                            raise KeyError(
                                f"Unable to append schema. Original error was: sqlite3.OperationalError: {error_text}")
                sqlite_connection.commit()
            sqlite_connection.close()
            return None


    def write_recursive(self, table_name, **kwargs):
        """
        Writes a new entry to the DB, overwrites if a guid collision occurs
        If any new column header keyword arguments are found, they are appended silently to the schema.
        Date is automatically generated as time in sec since epoc as a floating point number
        :param table_name: The SQL table being referenced
        :param kwargs:
        :return:
        """


        date = time.time()
        self.__build_db_if_needed(table_name, **kwargs)

        # region SQL Injection Protection

        # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
        # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
        sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_name))

        # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
        del table_name

        # endregion

        # we are using parametrized values in the query to let the execute() command handle sql injection protection
        # query = f"INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
        # parameters = (date, guid, hostname, str(ip), str(mac))

        # Note: "INSERT OR REPLACE" gives this function the ability to overwrite existing matching guids
        # Building: >>"INSERT INTO {sanitized_table_name} (<<date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?)"
        query = f"INSERT OR REPLACE INTO {sanitized_table_name} ("
        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        guid_found = False
        date_found = False
        values_list = []
        # Building header keywords section of the query first, while generating a list of the values to add next
        for key, value in kwargs.items():
            # Building: "INSERT INTO {sanitized_table_name} (>>date, guid, hostname, ip, mac<<) VALUES (?, ?, ?, ?, ?)"
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "

            sanitized_heading = self.__alpha_num_sanitize(key)
            # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
            del key


            # region Save the values to a separate list and check for reserved keywords
            # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
            if sanitized_heading.lower() == "guid":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()
                # and stored as raw integers in the DB
                if can_be_int(value):
                    value = int(value)
                else:
                    raise TypeError(f"guid given cannot be converted or used as an integer.  guid={value}")
                values_list.append(value)
                guid_found = True
                parent_guid = value
                query = f"{query}{sanitized_heading}"
            elif sanitized_heading.lower() == "date":
                # Reserved keywords are forced lowercase every time
                sanitized_heading = sanitized_heading.lower()
                # and stored as raw integers in the DB
                values_list.append(value)
                date_found = True
                query = f"{query}{sanitized_heading}"
            else:
                # Force value to string if it isn't a list or dict
                # If this is a list or dict, skip it, as it will be built after parent is built
                if not isinstance(value, (list,)) and not isinstance(value, (dict,)):
                    values_list.append(str(value))
                    query = f"{query}{sanitized_heading}"
                else:
                    # Setting first_element to skip insertion of extra commas when an item is skipped
                    first_element=True

            # endregion

        # date is added if not found in the given headings, since we will simply use epoc time if none is given
        if not date_found:
            if query[-1] == ",":
                # "value,"
                query = f"{query} date"
            elif query[-1] == " " and query[-2] == ",":
                # "value, "
                query = f"{query}date"
            else:
                # "value  " ???
                query = f"{query}, date"
            values_list.append(date)

        if not guid_found:
            raise ValueError("guid is a required keyword and was not found after sanitization and dedupe. Please Debug.")

        # Add the closing parenthesis to the first part of the query, and start VALUES section
        # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac>>) VALUES (<<?, ?, ?, ?, ?)"
        query = f"{query}) VALUES ("

        # Instead of adding the comma at the end of the loop, we add it at the beginning and simply have a special first
        first_element = True
        for value in values_list:
            # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (>>?, ?, ?, ?, ?<<)"
            if first_element:
                first_element = False
            else:
                # This way we don't need to remove a trailing comma and space in the query after loop completion
                query = f"{query}, "
            query = f"{query}?"

        # Add the closing parenthesis to the last part of the query, finishing the values section
        # Building: "INSERT INTO {sanitized_table_name} (date, guid, hostname, ip, mac) VALUES (?, ?, ?, ?, ?>>)<<"
        query = f"{query})"

        # Cast the values list into a tuple for SQL to read in properly
        parameters = tuple(values_list)


        # Minimizing cycles with DB open in memory front-load all operations, then get in, get out, but...
        # we need to handle a few exception cases to automatically extend the database schema as needed
        sqlite_connection = sqlite3.connect(self.db_file)
        with sqlite_connection:
            db_write_cursor = sqlite_connection.cursor()
            try_again = True
            attempts = 0
            while try_again:
                try:
                    db_write_cursor.execute(query, parameters)
                    try_again = False
                except sqlite3.OperationalError as error_tuple:
                    error_text = str(error_tuple)
                    # Typical error: 'table table_name has no column named my_column'
                    # Breaking each word into separate list item to check and parse
                    error_wordlist = error_text.split(" ")
                    error_comparison_list = ["table", sanitized_table_name, "has", "no", "column", "named"]
                    error_converted_list = error_wordlist[0]

                    if error_comparison_list == error_wordlist[0:6]:
                        # print(f"Ok, make a new column in {sanitized_table_name} table called {error_wordlist[6]}")
                        schema_update_query = f"ALTER TABLE {sanitized_table_name} ADD COLUMN {error_wordlist[6]};"
                        db_write_cursor.execute(schema_update_query)
                        sqlite_connection.commit()
                        attempts = attempts + 1
                        if attempts >= 100:
                            raise KeyError(f"After {attempts} attempts, the schema still reports missing headings. Giving up!")
                    else:
                        raise KeyError(f"Unable to append schema. Original error was: sqlite3.OperationalError: {error_text}")
            sqlite_connection.commit()
        sqlite_connection.close()

        # region Now that parent entry is built, check if any child tables need to be created
        for key, value in kwargs.items():
            sanitized_heading = self.__alpha_num_sanitize(key)
            # Note: To prevent accidental use, we explicitly delete the un-sanitized key variable
            del key
            if isinstance(value, (list,)):
                pass
                # # This is a list, create a child table
                # index = 0
                # list_to_dict = {}
                # for entry in value:
                #     list_to_dict[index] = entry
                #
                # self.__write_child(f"{sanitized_heading}_detail", parent_guid, self.app_name, **list_to_dict)
            elif isinstance(value, (dict,)):
                # This is a dict, create a child table
                for entry in value:
                    self.__write_child(f"{sanitized_heading}_detail", parent_guid, self.app_name, **value)
        # endregion

        return None

    # TODO: Remove less flexible self.count() method and replace with newer method self.count_size()
    def count(self, table_name):
        self.__build_db_if_needed(table_name)

        sqlite_connection = sqlite3.connect(self.db_file)

        with sqlite_connection:
            db_count_cursor = sqlite_connection.cursor()

            # region SQL Injection Protection

            # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
            # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
            sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_name))

            # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
            del table_name

            # endregion

            query = f"select count(*) from {sanitized_table_name}"


        db_count_cursor.execute(query)
        # list is used to convert the cursor into a list object we can count
        listcount = list(db_count_cursor)
        # which then returns a tuple for some reason
        tuplecount = listcount[0]
        # which then is converted into a integer
        count = tuplecount[0]
        # which then can be returned
        return count


    def count_size(self, db_file_to_count, table_to_count):
        sqlite_counting_connection = sqlite3.connect(db_file_to_count)

        with sqlite_counting_connection:
            db_counting_cursor = sqlite_counting_connection.cursor()

            # region SQL Injection Protection

            # The SQLite API does not support parameterized input for TABLE names. As a result, we must use the less secure
            # method of using string operations to generate the query. We use the self.__alpha_num_sanitize() function to strip everything out
            sanitized_table_name = self.__sql_sanitize(self.__alpha_num_sanitize(table_to_count))

            # To prevent accidental use, we explicitly delete the un-sanitized table_name variable
            del table_to_count

            # endregion

            query = f"select count(*) from {sanitized_table_name}"

            db_counting_cursor.execute(query)
            # list is used to convert the cursor into a list object we can count
            listcount = list(db_counting_cursor)
            # which then returns a tuple for some reason
            tuplecount = listcount[0]
            # which then is converted into a integer
            count = tuplecount[0]
            # which then can be used
            return count


if __name__ == "__main__":
    the_db = Blacklite("xerxes")
    the_db.write("shodan", guid=12333456789, scarry="yes", bah="no orange peeeeel!", penacilin="good", pie="over there")
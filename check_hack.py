#######################################################################################################################################################
#This script aims to detect potential hacking activity in a user login database. It utilizes recursive searches based on IP addresses and user IDs,   # 
#flagging suspicious activity based on login attempts from predefined "bad" or "warning" countries.                                                   #
#The script also leverages the IP geolocation API to obtain the country of origin for each IP address.                                                # 
#If the script is interrupted, it will print out the accounts that have been flagged as potentially compromised up to that point.                     #
#######################################################################################################################################################
import pandas as pd
import pymysql
import requests
import signal
import sys
from ip2geotools.databases.noncommercial import DbIpCity

# Lists of countries classified as bad, warning and safe.
bad_countries = ['DZ', 'AO', 'BJ', 'BW', 'BF', 'BI', 'CV', 'CM', 'CF', 'TD', 'KM', 'CD', 'CG', 'CI', 'DJ', 'EG', 'GQ', 'ER', 'SZ', 'ET', 'GA', 'GM', 'GH', 'GN', 'GW', 'KE', 'LS', 'LR', 'LY', 'MG', 'MW', 'ML', 'MR', 'MU', 'YT', 'MA', 'MZ', 'NA', 'NE', 'NG', 'RE', 'RW', 'ST', 'SN', 'SC', 'SL', 'SO', 'ZA', 'SS', 'SH', 'SD', 'TZ', 'TG', 'TN', 'UG', 'EH', 'ZM', 'ZW', 'AF', 'AM', 'AZ', 'BH', 'BD', 'BT', 'BN', 'KH', 'CN', 'CY', 'GE', 'HK', 'IN', 'ID', 'IR', 'IQ', 'IL', 'JP', 'JO', 'KZ', 'KP', 'KR', 'KW', 'KG', 'LA', 'LB', 'MO', 'MY', 'MV', 'MN', 'MM', 'NP', 'OM', 'PK', 'PS', 'PH', 'QA', 'SA', 'SG', 'LK', 'SY', 'TW', 'TJ', 'TH', 'TL', 'TR', 'TM', 'AE', 'UZ', 'VN', 'YE', 'AU']
warning_countries = ['US', 'CA', 'DE', 'GB']
safe_countries = ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE']

# List of user ids to be ignored
ignored_users = ['usr', 'usr', 'usr', 'usr', 'usr']  # replace with actual uids to ignore

# Function to fetch country code from IP address using an IP Geolocation API.

def get_country(ip):
    try:
        response = DbIpCity.get(ip, api_key='free')
        return response.country
    except Exception as e:
        print(f"Error getting country info for IP {ip}: ", str(e))
        return None

# Connect to MySQL database.
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='123456789',
    database='customer'
)

# Dictionaries to store IP addresses and corresponding account info for hacked and warning accounts.
hacked_accounts = {}
warning_accounts = {}

# Set to keep track of already checked IP addresses.
checked_ips = set()

def search_recursive(uid=None, ip=None):
    cursor = connection.cursor(pymysql.cursors.DictCursor)
    if uid:
        cursor.execute(f"SELECT occured, uid, ipAddress, loginResult FROM LoginEventEntity WHERE uid = '{uid}';")
    elif ip:
        cursor.execute(f"SELECT occured, uid, ipAddress, loginResult FROM LoginEventEntity WHERE ipAddress = '{ip}';")
    results = cursor.fetchall()
    for result in results:
        ip = result['ipAddress']
        uid = result['uid']
        if ip in checked_ips:
            continue
        country = get_country(ip)
        if country is None or country in safe_countries:
            continue
        checked_ips.add(ip)
        if result['loginResult'] == 'successful':
            if country in bad_countries:
                if ip not in hacked_accounts:
                    hacked_accounts[ip] = [(uid, result['occured'], country)]
                else:
                    hacked_accounts[ip].append((uid, result['occured'], country))
            elif country in warning_countries:
                if ip not in warning_accounts:
                    warning_accounts[ip] = [(uid, result['occured'], country)]
                else:
                    warning_accounts[ip].append((uid, result['occured'], country))
        print(f"Processing IP: {ip}, Country: {country}")  # Print the IP and the corresponding country being processed by the recursive function
        search_recursive(uid=uid)
        search_recursive(ip=ip)

# Function to handle the SIGINT signal and print the current results.
def signal_handler(sig, frame):
    print('\nInterrupted by user. Showing the processed results...\n')
    print_results()
    sys.exit(0)

# Function to print the results.
def print_results():
    print("\nHacked accounts:")
    hacked_accounts_list = [[ip, account[0], account[1]] for ip, accounts in hacked_accounts.items() for account in accounts if account[0] not in ignored_users]
    df_hacked = pd.DataFrame(hacked_accounts_list, columns=['IP', 'Account', 'Login Date'])
    print(df_hacked)

    print("\nPossibly hacked accounts:")
    warning_accounts_list = [[ip, account[0], account[1]] for ip, accounts in warning_accounts.items() for account in accounts if account[0] not in ignored_users]
    df_warning = pd.DataFrame(warning_accounts_list, columns=['IP', 'Account', 'Login Date'])
    print(df_warning)

# Connect the signal handler to the SIGINT signal.
signal.signal(signal.SIGINT, signal_handler)

try:
    # Cursor to fetch initial uids based on provided IP addresses.
    initial_uid_cursor = connection.cursor(pymysql.cursors.DictCursor)
    initial_ips = ['ip_addr', 'ip_addr', 'ip_addr', 'ip_addr'] 
    for ip in initial_ips:
        print(f"Starting with IP: {ip}")  # Change the message to distinguish from the recursive calls
        initial_uid_cursor.execute(f"SELECT DISTINCT uid FROM LoginEventEntity WHERE ipAddress = '{ip}';")
        initial_uid_results = initial_uid_cursor.fetchall()
        for initial_uid in initial_uid_results:
            search_recursive(initial_uid['uid'])

except Exception as e:
    print("Error occurred: ", str(e))

finally:
    # Print the results.
    print_results()
    # Close the database connection.
    connection.close()


#!/usr/bin/python
'''Project: FortiManager - With device name of FortiGate (with VDOM enabled), find all ADOMs (FortiGate->VDOM->ADOM) then upgrade them.
   Details: User prompts to ask for FortiManager IP, FortiManager API User/pass, and FortiGate Device name seen in FortiManager. It will then find all the ADOMs where that FortiGate VDOM exits,
            then ask the user what version to upgrade the ADOMs too.
   Date: 2024
   Functions: def fmg_login, fmg_logout, get_adom
   Python Version: 3.10.11
   FortiManager Version: v7.0,7.2,7.4,7.6
   Instructions for Creating API User Account, Read Only api is the minimum requirement: 
        - Add an API user in your FortiManager
            -Log into FortiManager with admin account, Go To:
                -System Settings => Admin => Administrators
                -Click "+ Create New"
                -Create a User Name
                -Set a Password
                -Admin Profile Standard_User (or whatever Access you would like to grant to this API User Account)
                -JSON API Access set to Read (or whatever Access via the API you would like to grant to this API User Account)
                -*Optional: Trusted Hosts, enabled and set IP address that your Python Script will be executed from to restrict access remotely to the API User.
                -Click OK, API User account is created
'''


## Define Modules
#For system calls like exit system, etc.
import sys
#Track date/time
from datetime import datetime
import time
#To use getpass to hide passwd when user is inputting it
import getpass
#For making HTTPS Connections to the FortiManager API Server
import requests
import urllib3
#To ignore the FortiManager Self Signed Certificate warnings.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#To receive and format JSON requests
import json

## Global Variables Init
STATE = None
TASKID = None
SESSION = None
URL = None
MAIN_LOG = None
UPGRADE_ERROR_LOG = None
SKIPPED_ADOM_LOG = None

## Functions
def fmg_login(host_apiuser, host_passwd, host_ip):
    '''FortiManager Login & Create Session
    Arguments:
    hostAPIUSER - API User Account Name
    hostPASSWD - API User Passwd
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    #Global Save Session ID
    global SESSION
    #Create HTTPS URL
    global URL
    URL = 'https://' + host_ip + '/jsonrpc'
    #JSON Body to sent to API request
    body = {
    "id": 1,
            "method": "exec",
            "params": [{
                    "url": "sys/login/user",
                    "data": [{
                            "user": host_apiuser,
                            "passwd": host_passwd
                    }]
            }],
            "session": 1
    }
    #Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(URL, json=body, verify=False)
    except requests.exceptions.RequestException as e: 
        print_log(SystemError(e))
        print_log(SystemError(e), 'errorlog', False)
        print_log(f'<-- ERROR Logging into FortiManager, see *upgrade_error.log and *main.log for details.')
        print_log('Closing console 5..4..3..2..1')
        time.sleep( 5 )
        #Exit Program, Connection was not Successful
        sys.exit(1)
    #Save JSON response from FortiManager
    json_resp = json.loads(r.text)
    # print(json_resp)
    #Check if User & Passwd was valid, no code -11 means invalid
    if json_resp['result'][0]['status']['code'] == 0:
        SESSION = json_resp['session']
        print_log(f'--> Logging into FortiManager: {host_ip}')
        #HTTP & JSON code & message
        print_log(f"<-- HTTPcode: {r.status_code} JSONmesg: {json_resp['result'][0]['status']['message']} \n")
        print
    else:
        print_log(f'<--Username or password is not valid, please try again, exiting...')
        print_log(f'<--Username or password is not valid, please try again, exiting...', 'errorlog', False)
        #HTTP & JSON code & message
        print_log(f"<-- HTTPcode: {r.status_code} JSONmesg: {json_resp['result'][0]['status']['message']}\n")
        print_log(f"<-- HTTPcode: {r.status_code} JSONmesg: {json_resp['result'][0]['status']['message']}\n", 'errorlog', False)
        print
        #Exit Program, Username or Password is not valided or internal FortiManager error review Hcode & Jmesg
        print_log('Closing console 5..4..3..2..1')
        time.sleep( 5 )
        sys.exit(1)

def fmg_logout(host_ip):
    '''FortiManager logout
    Arguments:
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    body = {
       "id": 1,
        "method": "exec",
        "params": [{
                "url": "sys/logout"
        }],
        "session": SESSION
    }
    #Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(URL, json=body, verify=False)
    except requests.exceptions.RequestException as e:
        print_log(SystemError(e))
        #Exit Program, Connection was not Successful
        sys.exit(1)
    #Save JSON response from FortiManager    
    json_resp = json.loads(r.text)
    #Check if any API Errors returned
    if json_resp['result'][0]['status']['code'] != -11:    
        print_log(f'\n--> Logging out of FMG: {host_ip}')
        #HTTP & JSON code & message
        print_log(f"<-- HTTPcode: {r.status_code} JSONmesg: {json_resp['result'][0]['status']['message']} \n")
    else:
        print_log(f'\n<--Error Occured, check Hcode & Jmesg')
        print_log(f'\n<--Error Occured, check Hcode & Jmesg', 'errorlog', False)
        #Exit Program, internal FortiManager error review Hcode & Jmesg
        print_log(f"<-- HTTPcode: {r.status_code} JSONmesg: {json_resp['result'][0]['status']['message']} \n")
        print_log(f"<-- HTTPcode: {r.status_code} JSONmesg: {json_resp['result'][0]['status']['message']} \n", 'errorlog', False)
        sys.exit(1)   

def get_adom(fgt_device_name):
    '''Get ADOMs
    Arguments:
    fgt_device_name - Device Name of the Fortigate(or cluster) listed in FortiManager under Device Manager

    Returns:
    adom_list - list of adoms from FortiGate Device
    '''
    adom_list = []
    json_url = "dvmdb/adom"
    body = {
            "id": 1,
            "method": "get",
            "params": [{
                    "expand member": [
                        {
                            "fields": [
                                "name",
                            ],
                            "filter": [
                                "name", "==", fgt_device_name
                            ],
                            "url": "/device"
                        }
                    ],
                    "fields": [
                        "name",
                    ],
                    "url": json_url
            }],
            "session": SESSION,
            #"verbose": 1
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    # print(json.dumps(json_resp, indent=2))
    for entry in json_resp['result'][0]['data']:
        #print(entry);
        if "expand member" in entry:
            adom_list.append(entry['name'])
            #print(entry)
    return adom_list

def workspace_lock(adom_name):
    '''Lock ADOM
    Arguments:
    adom_name- ADOM Name
    '''
    json_url = "pm/config/adom/" + adom_name + "/_workspace/lock"
    body = {
            "id": 1,
            "method": "exec",
            "params": [{
                    "url": json_url
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    print_log(f'--> Locking ADOM {adom_name}')
    print_log(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
    print

def workspace_commit(adom_name):
    '''SAVE/COMMIT ADOM Changes
    Arguments:
    adom_name- ADOM Name
    '''
    json_url = "pm/config/adom/" + adom_name + "/_workspace/commit"
    body = {
            "id": 1,
            "method": "exec",
            "params": [{
                    "url": json_url
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    print_log(f'--> Saving changes for ADOM {adom_name}')
    print_log(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
    print

def workspace_unlock(adom_name):
    '''Unlock ADOM
    Arguments:
    adom_name- ADOM Name
    '''
    json_url = "pm/config/adom/" + adom_name + "/_workspace/unlock"
    body = {
            "id": 1,
            "method": "exec",
            "params": [{
                    "url": json_url
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    print_log(f'--> Unlocking ADOM {adom_name}')
    print_log(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']} \n")
    print

def upgrade_adom_checkver(adom_name, adom_init_ver, api_user):
    '''Unlock ADOM
    Arguments:
    adom_name- ADOM Name
    adom_init_ver - ADOM version started at
    '''
    json_url = "dvmdb/adom/" + adom_name
    body = {
            "id": 1,
            "method": "get",
            "params": [{
                    "url": json_url
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    print_log('--> Checking current ADOM version')
    print_log(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
    print
    major_ver = json_resp['result'][0]['data']['os_ver']
    minor_ver = json_resp['result'][0]['data']['mr']
    adom_current_ver = str(major_ver) + '.' + str(minor_ver)
    if adom_current_ver == adom_init_ver:
            print_log(f'    Current version: {adom_current_ver}' )
            upgrade_adom(adom_name)
            poll_taskid(adom_name)
            create_adomrev(adom_name, api_user)
    else:
            print_log(f'    Current version: {adom_current_ver}')
            print_log(f'    Expected version: {adom_init_ver}')
            print
            print_log(f'    ADOM {adom_name} is not at expected start version of {adom_init_ver} !')
            print_log(f' !! SKIPPING this ADOM and adding to the skipped ADOM log skipped_adom.log !!' )
            print
            print_log(f'{adom_name} {adom_current_ver}', 'skippedadom')
            time.sleep ( 2 )

def poll_taskid (adom_name):
    '''pull tasks
    Arguments:
    adom_name- ADOM Name
    '''
    global STATE
    STATE = 0
    while STATE not in [3,4,5,7]:
            print_log(f'--> Polling task: {TASKID}')
            time.sleep( 3 )
            status_taskid()
    if STATE == 4:
            print_log(f'--> Task {TASKID} is done!')
    else:
            print_log(f'--> Task {TASKID} is DIRTY, check FortiManager task manager for details!')
            print_log(f'    Adding this ADOM to the upgrade error log upgrade_error_log.txt !')
            print_log(f'{adom_name} {TASKID} {STATE}', 'errorlog')

def status_taskid():
    '''check tasks status state
    Global STATE & TASKID
    '''
    global STATE
    json_url = "/task/task/" + str(TASKID)
    body = {
            "id": 1,
            "method": "get",
            "params": [{
                    "url": json_url
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    print_log (f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
    STATE = json_resp['result'][0]['data']['state']
    total_percent = json_resp['result'][0]['data']['tot_percent']
    if STATE == 0:
            print_log(f'    Current task state ({STATE}): pending')
    if STATE == 1:
            print_log(f'    Current task state ({STATE}): running')
    if STATE == 2:
            print_log(f'    Current task state ({STATE}): cancelling')
    if STATE == 3:
            print_log(f'    Current task state ({STATE}): cancelled')
    if STATE == 4:
            print_log(f'    Current task state ({STATE}): done')
    if STATE == 5:
            print_log(f'    Current task state ({STATE}): error')
    if STATE == 6:
            print_log(f'    Current task state ({STATE}): aborting')
    if STATE == 7:
            print_log(f'    Current task state ({STATE}): aborted')
    if STATE == 8:
            print_log(f'    Current task state ({STATE}): warning')
    if STATE == 9:
            print_log(f'    Current task state ({STATE}): to_continue')
    if STATE == 10:
            print_log(f'    Current task state ({STATE}): unknown')
    if json_resp['result'][0]['status']['message'] == 'OK':
            print_log(f'    Current task percentage: ({total_percent})')

def create_adomrev(adom_name, api_user):
    '''create adom revision for backout & history
    Arguments:
    adom_name- ADOM Name
    api_user - API username used for log entry
    '''
    json_url = "dvmdb/adom/" + adom_name + "/revision"
    body = {
        "id": 1,
        "method": "add",
        "params": [{
            "url": json_url,
            "data": {
                "locked": 0,
                "desc": "Created via JSON API",
                "name": "Post ADOM DB upgrade",
                "created_by": api_user
            }
        }],
        "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    print_log(f'--> Creating ADOM revision')
    print_log(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
    print
    time.sleep( 2 )

def upgrade_adom(adom_name):
    '''Upgrade adom
    Arguments:
    adom_name- ADOM Name
    '''
    global TASKID
    json_url = "pm/config/adom/" + adom_name + "/_upgrade"
    body = {
            "id": 1,
            "method": "exec",
            "params": [{
                    "url": json_url
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    TASKID = json_resp['result'][0]['data']['task']
    print
    print_log(f'--> Upgrading ADOM {adom_name}')
    print_log(f"<-- Hcode: {r.status_code} Jmesg: {json_resp['result'][0]['status']['message']}")
    print_log(f'--> TaskID: {TASKID}')

def get_fmg_version():
    ''' Gets FortiManager Version and available ADOM Versions

        Return:
        adom_versions_<7.2,7.4,7.6> - list of ADOM versions available based on FortiManager Release
    '''
    # Available ADOM versions
    adom_versions_70 = ['6.2','6.4','7.0']
    adom_versions_72 = ['6.4','7.0', '7.2']
    adom_versions_74 = ['7.0', '7.2', '7.4']
    adom_versions_76 = ['7.2', '7.4', '7.6']

    json_url = "/sys/status"
    body = {
            "id": 1,
            "method": "get",
            "params": [{
                    "url": json_url,
            }],
            "session": SESSION
    }
    r = requests.post(URL, json=body, verify=False)
    json_resp = json.loads(r.text)
    fmg_major_ver = json_resp['result'][0]['data']['Major']
    fmg_minor_ver = json_resp['result'][0]['data']['Minor']
    fmg_version = str(fmg_major_ver) + '.' + str(fmg_minor_ver)

    if fmg_version == '7.2':
        return adom_versions_72
    elif fmg_version == '7.4':
         return adom_versions_74
    elif fmg_version == '7.6':
         return adom_versions_76
    elif fmg_version == '7.0':
         return adom_versions_70
    else:
        print_log(f'ERROR VERSION {fmg_major_ver}.{fmg_minor_ver} not found or available for this script, {UPGRADE_ERROR_LOG}.', 'errorlog')
        # Existing Script
        print_log('Closing console 5..4..3..2..1')
        time.sleep( 5 )
        sys.exit(1)

def adom_upgrade_select():
    ''' User Input to get available ADOM version
        Return -
        adom_start_ver - Starting ADOM Version
        adom_end_ver - Ending ADOM Version
        upgrade_path_count - The number of upgrades to do for each ADOM
        adom_ver_list - list of ADOM versions available in the FortiManager
    '''
    # Get ADOM available version list
    adom_ver_list = get_fmg_version()

    ## ADOM Version Upgrade Menu
    print_log(f'Select your current ADOM DB Version for FortiManager {adom_ver_list[-1]}')
    for i, db_name in enumerate(adom_ver_list[:-1], start=1):
            print_log ('{}. {}'.format(i, db_name))
    
    while True:
        try:
            selected = int(input('Select current ADOM Version (1-{}): '.format(i)))
            startver = adom_ver_list[selected-1]
            print_log('You have selected {}'.format(startver))
            adom_start_ver = startver
            adom_start_selected_menu_num = selected
            break
        except (ValueError, IndexError):
            print_log('This is not a valid selection. Please enter number between 1 and {}!'.format(i))

    print_log(f'    Using Starting ADOM DB: {adom_start_ver} \n')

    adom_ver_list_final = []
    print_log('Select the final version of ADOM you would like to upgrade too: ')
    print_log('Available ADOM DB Versions: ')
    for i, db_name in enumerate(adom_ver_list, start=1):
        if i > adom_start_selected_menu_num:
            adom_ver_list_final.append(db_name)
    for i, db_name in enumerate(adom_ver_list_final, start=1):
            print ('{}. {}'.format(i, db_name))
    
    while True:
        try:
            selected = int(input('Select a database (1-{}): '.format(i)))
            endver = adom_ver_list_final[selected-1]
            print_log('You have selected {}'.format(endver))
            adom_end_ver = endver
            adom_end_selected_menu_num = selected
            break
        except (ValueError, IndexError):
            print('This is not a valid selection. Please enter number between 1 and {}!'.format(i))

    print_log(f'    Using Ending ADOM DB: {adom_end_ver}\n')
    upgrade_path_count = adom_ver_list.index(adom_end_ver) - adom_ver_list.index(adom_start_ver)

    return adom_start_ver, adom_end_ver, upgrade_path_count, adom_ver_list
    
def continue_script():
    ''' Prompts User to check variables before continuing script
    '''
    print_log('-=-' * 20)
    while True:
        try:
            print_log('--> Continue script with current variables? (y or n): ')
            goNOgo = input()
        except ValueError:
            print_log('    Input not understood, please input y or n.')
            continue
        if goNOgo == 'y':
            print_log('    Variables accepted, continuing script.\n')
            print_log('-=-' * 20)
            print_log('\n')
            goNOgo = ''
            break
        elif goNOgo == 'n':
            print_log('    Variables NOT accepted, selecting not to continue, exiting script!\n')
            #Exit Program, Username or Password is not valided or internal FortiManager error review Hcode & Jmesg
            print_log('Closing console 5..4..3..2..1')
            time.sleep( 5 )
            sys.exit(1)
        else:
            print_log('    Input not understood, please input y or n!')
            continue

def pretty_print_json(json_list):
    ''' To print out json output in easy reable format. Used for troubleshooting mostly'''
    # for json_obj in json_list:
    #     print(json.dumps(json_obj, indent=2))
    print(json.dumps(json_list, indent=2))

def create_logfiles():
    global MAIN_LOG
    global UPGRADE_ERROR_LOG
    global SKIPPED_ADOM_LOG

    ''' Creates log files everytime program is run with timestamp'''
    # Get the current timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Create a log filename using the timestamp
    MAIN_LOG = f'{timestamp}_main.log'
    UPGRADE_ERROR_LOG = f'{timestamp}_upgrade_error.log'
    SKIPPED_ADOM_LOG = f'{timestamp}_skipped_adom.log'
    with open(MAIN_LOG, 'w') as main:
         main.write('= MAIN LOG File Created\n')
    with open(UPGRADE_ERROR_LOG, 'w') as error:
         error.write('= ERROR LOG file Created\n')
    with open(SKIPPED_ADOM_LOG, 'w') as skipped:
         skipped.write('= SKIPPED ADOM LOG file Created\n')

def print_log(message, log_type='mainlog', print_option=True):
    '''print_logto screen and logs to file
    Arguments:
    message - message to print_logto screen and to log file
    
    Optional:
    log_type - if pass string "errorlog" will send output to error log, if pass string "skippedadom" will send output to skip log
    '''
    # print_logto console
    if print_option:
        print(message)
    
    if log_type == 'errorlog':
         with open(UPGRADE_ERROR_LOG, 'a') as error:
              error.write(message + '\n')
    if log_type == 'skippedadom':
         with open(SKIPPED_ADOM_LOG, 'a') as skipped:
              skipped.write(message + '\n')
    if log_type == 'mainlog':
        with open(MAIN_LOG, 'a') as f:
            f.write(f"{message}\n")

## MAIN      
def main():
    ''' The main function/program '''
    # Create Log Files
    create_logfiles()

    # Record script start time
    start_time = datetime.now()
    print_log(f'Script started at {start_time}')
    print_log(f'Script started at {start_time}', 'errorlog', False)

    ## User Input Section ##
    # Prompt for IP Address of FortiManager
    print_log('Please Enter FortiManager IP Address: (ex 1.1.1.1 or 1.1.1.1:8443)')
    host_ip = input()
    #Check User put in data
    while not host_ip:
        print_log('Error, Please Enter FortiManager IP Address: (ex 1.1.1.1 or 1.1.1.1:8443)')
        host_ip = input()
    
    # Prompt for API User Name
    print_log('Please Enter FortiManager API User name:')
    host_apiuser = input()
    #Check User put in data
    while not host_apiuser:
        print_log('Error, Please Enter FortiManager API User name:')
        host_apiuser = input()
    
    # Prompt for API User password. use getpass() module to hide it being displayed
    host_passwd = getpass.getpass('Please Enter FortiManager API User password:')
    #Check User put in data
    while not host_passwd:
        host_passwd = getpass.getpass('Error, Please Enter FortiManager API User password:')
    
    # Prompt for FortiGate Device Name
    print_log('Please Enter the Device Name for the FortiGate listed in FortiManager:')
    fgt_device_name = input()
    while not fgt_device_name:
        print_log('Error, Please Enter the Device name for the FortiGate:')
        fgt_device_name = input()

    ## Call fmg_login Function
    fmg_login(host_apiuser, host_passwd, host_ip)

    ## Get FortiManager Version
    adom_start_version, adom_end_version, upgrade_path_count, adom_version_list = adom_upgrade_select()
    print_log('-=-' * 20)
    print_log('--> Final variables: ')
    print_log(f' FMG IP: {host_ip}')
    print_log(f' FMG API account name: {host_apiuser}')
    print_log(f' FortiGate Device Name: {fgt_device_name}')
    print_log(f' Current ADOM version: {adom_start_version}')
    print_log(f' Final ADOM version : {adom_end_version}')
    # Continue script with varilables above?
    continue_script()

    # Get ADOMs
    adom_list = get_adom(fgt_device_name)
    if adom_list:
        print_log('-=-' * 20)
        print_log(f'--> Following ADOM found for FortiGate Device {fgt_device_name}')
        for adom in adom_list:
            print_log(adom)
        # Continue script with varilables above?
        continue_script()
        print_log(f'\n<-- Starting Upgrade of ADOMs for FortiGate Device {fgt_device_name}\n')
    else:
        print_log('-=-' * 20)
        print_log(f'--> No ADOMs found for FortiGate Device {fgt_device_name}')
        print_log(f'--> Please check FortiGate Device name is correct and exists in FortiManager')
        #errorlog
        print_log(f'--> No ADOMs found for FortiGate Device {fgt_device_name}', 'errorlog', False)
        print_log(f'--> Please check FortiGate Device name is correct and exists in FortiManager', 'errorlog', False)
        #
        print_log('-->EXITING program, no ADOMs to process...')
        print_log('Completed Script, for Log files please view "main.log", "skipped_adom.log", and "upgrade_error.log".\n')
        print_log('Closing console 5..4..3..2..1')
        time.sleep( 5 )
        sys.exit(1)

    #Upgrade ADOMs
    adom_index = adom_version_list.index(adom_start_version)

    for i in range(upgrade_path_count):
        for adom in adom_list:
            print_log(f'<-- Starting upgrade on ADOM {adom}')
            workspace_lock(adom)
            upgrade_adom_checkver(adom, adom_start_version, host_apiuser)
            workspace_unlock(adom)
        # Increment the version for the next iteration
        adom_index += 1
        if adom_index >= len(adom_version_list) or adom_version_list[adom_index] == adom_end_version:
            break
        else:
            adom_start_version = adom_version_list[adom_index]

    # Completed ADOM upgrades
    print_log(f'Completed ADOM upgrades for FortiGate Device {fgt_device_name}\n')

    ## Call fmg_logout Function
    fmg_logout(host_ip)

    # Record script end time
    end_time = datetime.now()
    print_log(f'Script ended at {end_time}')
    print_log(f'Total runtime: {end_time - start_time}')
    # To eror log
    print_log(f'Script ended at {end_time}', 'errorlog', False)
    print_log(f'Total runtime: {end_time - start_time}', 'errorlog', False)

    # Used to keep Windows Terminal open for user to read output as it will close as soon as program is done. 
    print_log('Completed Script, for Log files please view "main.log", "skipped_adom.log", and "upgrade_error.log".\n')
    print_log('Closing console 5..4..3..2..1')
    time.sleep( 5 )
    ''' End main function/program '''

## Run the main function/program
if __name__ == '__main__':
    main()
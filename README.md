FortiManager ADOM Upgrade
This script automates the process of logging into FortiManager, finding ADOMs based on FortiGate device/VDOMs, then upgrading the ADOM to the version based on the user's input
Description
The script streamlines the process of upgrading multiple ADOM in an environment were the FortiGate has multi-vdom enable and in different ADOMs:

    Logging into FortiManager
    Identifying ADOMs associated with specific FortiGate device/VDOMs
    Getting user input for ADOM version to upgrade too
    Upgrading ADOMs mapped to VDOM for the FortiGate device

Usage

    Python Windows EXE file
        Option 1) Python Windows EXE file.
                Download EXE Program under /dist folder (Click on *.exe then click on View Raw Link to DL)
                Double click EXE file follow instructions

        Option 2) Create EXE via pyinstaller (Windows)
                Clone the repository to your local machine (Windows if creating Windows EXE)
                pip install pyinstaller
                See 'Build python to exe HOWTO.txt' file for pyinstaller command
                run EXE file under created /dist

    Python py file
        1) Clone the repository:
            git clone

        2) Install the dependencies:
            pip install -r requirements.txt

        3) Run the application:
            python fmg_adom_upgrade.py

Requirements

    Python 3.10
    FortiManager Versions Supported: 7.0,7.2,7.4,7.6
    FortiManager API access with R/W API user account.
    FortiGate Device Name displayed in FortiManager

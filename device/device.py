import os
import re
import jwt
import uuid
import struct
import base64
import requests
import xmltodict
import urllib.parse
import json
import xml.etree.ElementTree as ET

from abc import abstractmethod
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from roadtools.roadlib.auth import Authentication
from roadtools.roadlib.deviceauth import DeviceAuthentication

from rich import print
from rich.padding import Padding
from rich.table import Table
from rich.style import Style

from utils.utils import prtauth, renew_token, token_renewal_for_enrollment, create_pfx, extract_pfx, get_devicetoken, write_file

outdir = os.path.join(os.getcwd(), 'loot')

# https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-devicetype?view=graph-rest-beta
deviceType = {
    "desktop": "0",
    "windowsRT": "1",
    "winMO6": "2",
    "nokia": "3",
    "windowsPhone": "4",
    "mac": "5",
    "winCE": "6",
    "winEmbedded": "7",
    "iPhone": "8",
    "iPad": "9",
    "iPod": "10",
    "android": "11",
    "iSocConsumer": "12",
    "unix": "13",
    "macMDM": "14",
    "holoLens": "15",
    "surfaceHub": "16",
    "androidForWork": "17",
    "androidEnterprise": "18",
    "windows10x": "19",
    "androidnGMS": "20",
    "chromeOS": "21",
    "linux": "22",
    "visionOS": "23",
    "tvOS": "24",
    "blackberry": "100",
    "palm": "101",
    "unknown": "255",
    "cloudPC": "257"
}

clientId = {
    "Microsoft Intune Company Portal": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
    "Microsoft Authentication Broker": "29d9ed98-a469-4536-ade2-f981bc1d605e",
}

class Device:
    def __init__(self, logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy):
        self.logger = logger
        self.os = os
        self.os_version = None
        self.ssp_version = None
        self.device_name = device_name
        self.deviceid = deviceid
        self.intune_deviceid = None
        self.uid = uid
        self.tenant = tenant
        self.prt = prt
        self.session_key = session_key
        self.checkin_url = None
        self.provider_name = None
        self.cname = None
        self.hwhash = None
        self.proxy = proxy
        self.device_auth = DeviceAuthentication()
        self.device_auth.proxies = proxy
        self.device_auth.verify = False
        self.device_auth.auth.proxies = proxy
        self.device_auth.auth.verify = False

        self.CommonContainer_Retire = None
        self.CommonContainer_FullWipe = None
        self.CommonContainer_SetRD = None
        self.CommonContainer_CheckCompliance = None
        self.CommonContainer_SetOptIn = None
        self.CommonContainer_SetHeartBeat = None
        self.CommonContainer_GetManagementState = None
        self.CommonContainer_RegisterForAppPushNotifications = None
        self.CommonContainer_GetBitLockerRecoveryKeys = None
        self.CommonContainer_RemoveSignedDeviceIdPolicyAssignment = None
        self.CommonContainer_UpdateAadId = None
        self.NoncompliantRules = None
        self.Key = None
        self.ChassisType = None
        self.Nickname = None
        self.DeviceHWId = None
        self.Manufacturer = None
        self.Model = None
        self.OfficialName = None
        self.OperatingSystem = None
        self.ManagementType = None
        self.RemotableProperties = None
        self.ManagementAgent = None
        self.LastContact = None
        self.LastContactNotification = None
        self.ComplianceState = None
        self.AadId = None
        self.OperatingSystemId = None
        self.OSSubtype = None
        self.AppWrapperCertSN = None
        self.ExchangeActivationItemEasId = None
        self.IsExchangeActivated = None
        self.EasId = None
        self.CreatedDate = None
        self.ExchangeActivationItems = None
        self.IsSspConfirmed = None
        self.CategoryId = None
        self.CategorySetByEndUser = None
        self.DeviceActions = None
        self.RemoteSessionUri = None
        self.PartnerName = None
        self.PartnerSelfServicePortalUrl = None
        self.PartnerRemediationUrl = None
        self.IsPartnerManaged = None
        self.PartnerLocalizedSelfServicePortalName = None
        self.OwnerType = None
        self.IsReadOnly = None
        self.CoManagementFeatures = None
        self.UserApprovedEnrollment = None
        self.SupervisedStatus = None
        self.IsSharedDevice = None
        self.UdaStatus = None
        self.OSVersion = None
        self.Architecture = None
        self.IsCompliantInGraph = None
        self.IsManagedInGraph = None
        self.EnrollmentType = None
        self.InGracePeriodUntilDateTimeUtc = None

        # Checkin process commands
        self.checkin_locuri_responses = {"Delete": [], "Replace": [], "Add": []}

    def save_device_config(self):
        # Create device_config folder if it does not exist
        filepath = os.path.join('device_config', self.device_name)

        if os.path.exists(filepath):
            self.logger.debug(f'Device name found in device_config folder')
        else:
            os.makedirs(filepath)

        # If the Certificate is in the primary root folder, move it to the device_config folder
        device_pfxpath = f'{self.device_name}.pfx'
        device_certpath = f'{self.device_name}_cert.pem'
        device_keypath = f'{self.device_name}_key.key'
        
        mdm_pfxpath = f'{self.device_name}_mdm.pfx'
        mdm_certpath = f'{self.device_name}_mdm_cert.pem'
        mdm_keypath = f'{self.device_name}_mdm_key.key'

        for pfxpath, certpath, keypath in [
            (device_pfxpath, device_certpath, device_keypath),
            (mdm_pfxpath, mdm_certpath, mdm_keypath)
        ]:
            if os.path.exists(pfxpath):
                os.rename(pfxpath, os.path.join(filepath, pfxpath))
            if os.path.exists(keypath):
                os.rename(keypath, os.path.join(filepath, keypath)) 
            if os.path.exists(certpath):
                os.rename(certpath, os.path.join(filepath, certpath))

        # Save device configuration to JSON file
        config_filename = f'{self.device_name}_config.json'

        # Load all the settings into dictionaries for JSON dumping
        main_settings = {
            "os" : self.os,
            "os_version" : self.os_version,
            "ssp_version" : self.ssp_version,
            "device_name" : self.device_name,
            "deviceid" : self.deviceid,
            "intune_deviceid" : self.intune_deviceid,
            "uid" : self.uid,
            "tenant" : self.tenant,
            "prt" : self.prt,
            "session_key" : self.session_key,
            "checkin_url" : self.checkin_url,
            "provider_name" : self.provider_name,
            "cname" : self.cname,
            "hwhash" : self.hwhash,
        }

        enrollment_info = {
            "CommonContainer_Retire" : self.CommonContainer_Retire,
            "CommonContainer_FullWipe" : self.CommonContainer_FullWipe,
            "CommonContainer_SetRD" : self.CommonContainer_SetRD,
            "CommonContainer_CheckCompliance" : self.CommonContainer_CheckCompliance,
            "CommonContainer_SetOptIn" : self.CommonContainer_SetOptIn,
            "CommonContainer_SetHeartBeat" : self.CommonContainer_SetHeartBeat,
            "CommonContainer_GetManagementState" : self.CommonContainer_GetManagementState,
            "CommonContainer_RegisterForAppPushNotifications" : self.CommonContainer_RegisterForAppPushNotifications,
            "CommonContainer_GetBitLockerRecoveryKeys" : self.CommonContainer_GetBitLockerRecoveryKeys,
            "CommonContainer_RemoveSignedDeviceIdPolicyAssignment" : self.CommonContainer_RemoveSignedDeviceIdPolicyAssignment,
            "CommonContainer_UpdateAadId" : self.CommonContainer_UpdateAadId,
            "NoncompliantRules" : self.NoncompliantRules,
            "Key" : self.Key,
            "ChassisType" : self.ChassisType,
            "Nickname" : self.Nickname,
            "DeviceHWId" : self.DeviceHWId,
            "Manufacturer" : self.Manufacturer,
            "Model" : self.Model,
            "OfficialName" : self.OfficialName,
            "OperatingSystem" : self.OperatingSystem,
            "ManagementType" : self.ManagementType,
            "RemotableProperties" : self.RemotableProperties,
            "ManagementAgent" : self.ManagementAgent,
            "LastContact" : self.LastContact,
            "LastContactNotification" : self.LastContactNotification,
            "ComplianceState" : self.ComplianceState,
            "AadId" : self.AadId,
            "OperatingSystemId" : self.OperatingSystemId,
            "OSSubtype" : self.OSSubtype,
            "AppWrapperCertSN" : self.AppWrapperCertSN,
            "ExchangeActivationItemEasId" : self.ExchangeActivationItemEasId,
            "IsExchangeActivated" : self.IsExchangeActivated,
            "EasId" : self.EasId,
            "CreatedDate" : self.CreatedDate,
            "ExchangeActivationItems" : self.ExchangeActivationItems,
            "IsSspConfirmed" : self.IsSspConfirmed,
            "CategoryId" : self.CategoryId,
            "CategorySetByEndUser" : self.CategorySetByEndUser,
            "DeviceActions" : self.DeviceActions,
            "RemoteSessionUri" : self.RemoteSessionUri,
            "PartnerName" : self.PartnerName,
            "PartnerSelfServicePortalUrl" : self.PartnerSelfServicePortalUrl,
            "PartnerRemediationUrl" : self.PartnerRemediationUrl,
            "IsPartnerManaged" : self.IsPartnerManaged,
            "PartnerLocalizedSelfServicePortalName" : self.PartnerLocalizedSelfServicePortalName,
            "OwnerType" : self.OwnerType,
            "IsReadOnly" : self.IsReadOnly,
            "CoManagementFeatures" : self.CoManagementFeatures,
            "UserApprovedEnrollment" : self.UserApprovedEnrollment,
            "SupervisedStatus" : self.SupervisedStatus,
            "IsSharedDevice" : self.IsSharedDevice,
            "UdaStatus" : self.UdaStatus,
            "OSVersion" : self.OSVersion,
            "Architecture" : self.Architecture,
            "IsCompliantInGraph" : self.IsCompliantInGraph,
            "IsManagedInGraph" : self.IsManagedInGraph,
            "EnrollmentType" : self.EnrollmentType,
            "InGracePeriodUntilDateTimeUtc" : self.InGracePeriodUntilDateTimeUtc,
        }

        service_info = {}
        # For all attributes in the self object
        for i in dir(self):
            #print(i)
            # if they contain spn_ as a prefix
            if i.startswith('spn_'):
                service_info[i] = getattr(self, i)

        output = {
            "main_settings": main_settings,
            "enrollment_info": enrollment_info,
            "service_info": service_info
        }

        write_file(filepath=filepath, filename=config_filename, content=json.dumps(output, indent=4))

        return

    def load_device_config(self, device_name):
        self.device_name = device_name

        # Verify if the device_config folder exist
        filepath = os.path.join('device_config', self.device_name)

        if os.path.exists(filepath) == False:
            self.logger.error(f'Device config for {device_name} not found!')
            return False

        # For all testing, we need the Device PFX and the MDM PFX at a minimum.
        device_pfxpath = os.path.join(filepath, f'{self.device_name}.pfx')
        device_certpath = os.path.join(filepath, f'{self.device_name}_cert.pem')
        device_keypath = os.path.join(filepath, f'{self.device_name}_key.key')

        mdm_pfxpath = os.path.join(filepath, f'{self.device_name}_mdm.pfx')
        mdm_certpath = os.path.join(filepath, f'{self.device_name}_mdm_cert.pem')
        mdm_keypath = os.path.join(filepath, f'{self.device_name}_mdm_key.key')

        # Verify if the path for the pfx file exists
        if os.path.exists(device_pfxpath):
            # If we do not have the device cert and key in our config folder, extract them from the PFX
            self.logger.debug(f'Found device PFX for {self.device_name}')
            if (os.path.exists(device_certpath) == False) or (os.path.exists(device_keypath) == False):
                self.logger.debug(f'Extracting device cert and key from PFX for {self.device_name}')
                extract_pfx(
                    device_pfxpath,
                    device_certpath,
                    device_keypath
                )
        else:
            # If we have the device cert and key instead, create the PFX
            if (os.path.exists(device_certpath) == True) and (os.path.exists(device_keypath) == True):
                create_pfx(device_certpath, device_keypath, device_pfxpath)
            # Else return false indicating we do not have the required files
            else:
                self.logger.error(f'Device certificate PFX for {device_name} not found in device_config folder!')
                return False

        # Verify if the path for the mdm pfx file exists
        if os.path.exists(mdm_pfxpath):
            self.logger.debug(f'Found MDM PFX for {self.device_name}')
            # If we do not have the MDM cert and key in our config folder, extract them from the PFX
            if (os.path.exists(mdm_certpath) == False) or (os.path.exists(mdm_keypath) == False):
                self.logger.debug(f'Extracting MDM cert and key from PFX for {self.device_name}')
                extract_pfx(
                    mdm_pfxpath,
                    mdm_certpath,
                    mdm_keypath
                )
        else:
            self.logger.error(f'MDM certificate PFX for {device_name} not found in device_config folder!')
            return False

        # Configure the self paths for the device config paths
        self.device_pfxpath = device_pfxpath
        self.device_certpath = device_certpath
        self.device_keypath = device_keypath

        self.mdm_pfxpath = mdm_pfxpath
        self.mdm_certpath = mdm_certpath
        self.mdm_keypath = mdm_keypath


        ## Device Configuration File
        config_filename = os.path.join(filepath, f'{self.device_name}_config.json')

        # Verify the file exists
        if not os.path.exists(config_filename):
            self.logger.error(f'Device configuration file for {device_name} not found in device_config folder!')
            return False

        with open(config_filename, 'r') as config_file:
            config_data = json.load(config_file)

        # Load all settings from the JSON file
        main_settings = config_data.get("main_settings", {})
        enrollment_info = config_data.get("enrollment_info", {})
        service_info = config_data.get("service_info", {})

        for i in (main_settings, enrollment_info, service_info):
            for key, value in i.items():
                # For each item inside the config, set the attribute in the self object
                self.logger.debug(f'Loading setting: {key} = {value}')
                setattr(self, key, value)
        
        return True

    def display_device_configs(self):
        # Display the current device configurations stored within the folder.
        filepath = 'device_config'
        if os.path.exists(filepath) == False:
            self.logger.error(f'Device config folder not found!')
            return False
        device_names = os.listdir(filepath)
        if len(device_names) == 0:
            self.logger.error(f'No device configurations found in device_config folder!')
            return False

        out_table = []

        for device_name in device_names:
            device_path = os.path.join(filepath, device_name)

            config_found = False
            device_cert_found = False
            device_cert_key_found = False
            device_pfx_found = False
            mdm_cert_found = False
            mdm_cert_key_found = False
            mdm_pfx_found = False

            for file in os.listdir(device_path):
                #print(file)
                if file == f'{device_name}_config.json':
                    config_found = True
                if file == f'{device_name}_cert.pem':
                    device_cert_found = True
                if file == f'{device_name}_key.key':
                    device_cert_key_found = True
                if file == f'{device_name}_mdm_cert.pem':
                    mdm_cert_found = True
                if file == f'{device_name}_mdm_key.key':
                    mdm_cert_key_found = True
                if file == f'{device_name}.pfx':
                    device_pfx_found = True
                if file == f'{device_name}_mdm.pfx':
                    mdm_pfx_found = True

            out_table.append([
                device_name,
                config_found,
                device_pfx_found,
                device_cert_found,
                device_cert_key_found,
                mdm_pfx_found,
                mdm_cert_found,
                mdm_cert_key_found,
            ])

        table = Table(title="Devices in Config Folder")
        table.add_column("Device Name", justify="left", no_wrap=True)
        table.add_column("Config File", justify="center", no_wrap=True)
        table.add_column("Device PFX", justify="center", no_wrap=True)
        table.add_column("Device Cert", justify="center", no_wrap=True)
        table.add_column("Device Key", justify="center", no_wrap=True)
        table.add_column("MDM PFX", justify="center", no_wrap=True)
        table.add_column("MDM Cert", justify="center", no_wrap=True)
        table.add_column("MDM Key", justify="center", no_wrap=True)
        
        for i in out_table:
            row_data = [str(i[0])]
            for idx in range(1, 8):
                if i[idx]:
                    row_data.append("[green]True[/green]")
                else:
                    row_data.append("[red]False[/red]")
            
            table.add_row(*row_data)

        print(table)

    def entra_join(self, username, password, access_token, deviceticket, join_type: str='join'):
        devicereg = 'urn:ms-drs:enterpriseregistration.windows.net'

        # Verify if we have supplied an access token
        if access_token:
            # Verify if the access token has the correct scope
            claims = jwt.decode(access_token, options={"verify_signature":False}, algorithms=['RS256'])
            if claims['aud'] != devicereg:
                self.logger.info(f"wrong resource uri! {devicereg} is expected")
                return
        else:
            # Authenticate instead and get a access token that is properly scoped
            auth = Authentication(username=username, password=password)
            auth.resource_uri = devicereg
            auth.proxies = self.proxy
            auth.verify = False
            access_token = auth.authenticate_username_password()['accessToken']

        # Device registration output certificate file location
        device_certpath = f'{self.device_name}_cert.pem'
        device_keypath = f'{self.device_name}_key.key'

        valid = self.device_auth.register_device(
            access_token = access_token,
            jointype = (0 if join_type == 'join' else 4), # 0 : join, 4 : register
            certout = device_certpath,
            privout = device_keypath, 
            device_type = self.os,
            device_name = self.device_name,
            os_version = self.os_version,
            deviceticket = deviceticket
        )

        # Catch registration failure
        if valid == False:
            self.logger.error(f'Device registration failed.')
            return False

        # This PFX Conversion is one of my most hated things, we keep reusing this again and again, why remove it?
        pfxpath = f'{self.device_name}.pfx'
        create_pfx(device_certpath, device_keypath, pfxpath)
        os.remove(device_certpath)
        os.remove(device_keypath)

        self.logger.success(f'successfully registered {self.device_name} to Entra ID!')
        self.logger.debug(f'here is your device certificate: {pfxpath} (pw: password)')
        return True

    def entra_delete(self, certpfx):
        # Again, why the fuck do we keep doing this if we want to use a certificate, keep it as 2 files and don't just make/delete it
        device_certpath = f'{self.device_name}_cert.pem'
        device_keypath = f'{self.device_name}_key.key'
        extract_pfx(certpfx, device_certpath, device_keypath)

        self.device_auth.loadcert(pemfile = device_certpath, privkeyfile = device_keypath)
        self.device_auth.delete_device(device_certpath, device_keypath)

        os.remove(device_certpath)
        os.remove(device_keypath)
        return

    def enroll_intune(self, certpfx, refresh_token, is_device, is_hybrid):
        if certpfx:
            access_token, refresh_token = prtauth(
                prt = self.prt, 
                session_key = self.session_key, 
                client_id = clientId["Microsoft Intune Company Portal"], 
                resource = 'https://graph.microsoft.com/', 
                redirect_uri = None, 
                proxy = self.proxy
            )
        else:
            access_token, refresh_token = renew_token(
                refresh_token = refresh_token, 
                client_id = clientId["Microsoft Intune Company Portal"], 
                scope = 'https://graph.microsoft.com/.default', 
                proxy = self.proxy
            )

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        self.get_enrollment_info(access_token)

        enrollment_url = getattr(self, f'spn_{self.provider_name}')
        self.logger.debug(f"Enrollment url: {enrollment_url}")

        csr_der = self.create_csr(private_key, self.cname)
        csr_pem = base64.b64encode(csr_der).decode('utf-8')
        
        if is_device:
            self.logger.info('Using device token for Intune enrollment')
            csr_token = get_devicetoken(self.tenant, certpfx)
        else:
            csr_token = self.get_enrollment_token(refresh_token)

        try:
            self.logger.info('Enrolling device to Intune...')
            response = self.send_enroll_request(
                enrollment_url = enrollment_url, 
                csr_pem = csr_pem, 
                csr_token = csr_token, 
                ztdregistrationid = None, 
                is_device = is_device, 
                is_hejd = is_hybrid
            )

        except:
            self.logger.error('Device enrollment failed.')
            return False

        my_cert = self.parse_enroll_response(response)
        if my_cert == None:
            self.logger.error(f'Certificate signing request failed.')
            return False

        # Straight up hate they do this custom PFX shit
        pfxpath = f'{self.device_name}_mdm.pfx'
        self.save_mdm_certs(private_key, my_cert, pfxpath)

        self.logger.success(f'Successfully enrolled {self.device_name} to Intune!')
        self.logger.info(f'Here is your MDM pfx: {pfxpath} (pw: password)')
        return True

    def checkin(self, mdmpfx, stdout=True, write_output_to_dir=False):

        # Verify if the current self contains mdm_certpath or mdm_keypath, if we do, this means we are using the device config insted of the supplied PFX
        if hasattr(self, 'mdm_certpath') and hasattr(self, 'mdm_keypath'):
            self.logger.debug(f'Using MDM cert and key from device config for checkin')
            certpath = self.mdm_certpath
            keypath = self.mdm_keypath
        elif hasattr(self, 'mdm_pfxpath'):
            # In the impossible case we have the mdm_pfxpath set instead, extract from there
            self.logger.debug(f'Using MDM PFX from device config for checkin')
            filepath = os.path.join('device_config', self.device_name)
            certpath = os.path.join(filepath, f'{self.device_name}_mdm_cert.pem')
            keypath = os.path.join(filepath, f'{self.device_name}_mdm_key.key')
            extract_pfx(self.mdm_pfxpath, certpath, keypath)
        else:
            # If we do not have the attribute set, use the supplied PFX to generate the cert and key
            self.logger.debug(f'Using supplied MDM PFX for checkin')
            certpath = f'{self.device_name}_mdm_cert.pem'
            keypath = f'{self.device_name}_mdm_key.key'
            extract_pfx(mdmpfx, certpath, keypath)

        imei = str(uuid.uuid4())
        msgid = 1
        sessionid = 1
        syncml_data = self.generate_initial_syncml(sessionid, imei)
        profiles = []
        msi_urls = []
        odjblob = None

        # Check if we have old SyncML results to load as these can be required
        self.load_old_syncml_results()

        # SyncML checkin loop
        while True:
            # Send the request for our current SyncML data
            self.logger.info(f'Send request #{msgid}')
            syncml_data_out = json.dumps(xmltodict.parse(syncml_data), indent=4)

            filename = f'xmlout-{msgid}-request.xml'
            write_file(filepath=os.path.join(outdir, "syncml_data"), filename=filename, content=syncml_data)

            # Generate a response
            response = self.send_syncml(syncml_data, certpath, keypath)

            #print(response.decode())
            filename = f'xmlout-{msgid}-response.xml'
            write_file(filepath=os.path.join(outdir, "syncml_data"), filename=filename, content=response)

            if 'Unenroll' in response.decode():
                self.logger.alert(f'Recieved the request to unenroll this device ...')

            if 'Bad Request' in response.decode():
                break

            cmds = self.parse_syncml(response)
            if cmds == None:
                break

            profiles.extend(self.extract_profiles(cmds))
            msi_urls.extend(self.extract_msi_url(cmds))

            if odjblob is None:
                odjblob = self.extract_odjblob(cmds)

            # Itterate up the message ID
            msgid += 1
            write_file(filepath=os.path.join(outdir, "syncml_data"), filename=f'cmds-{msgid}.json', content=json.dumps(cmds, indent=4))
            syncml_data = self.generate_syncml_response(msgid, sessionid, imei, cmds)

        self.logger.info(f'Checkin ended!')

        if len(profiles) > 0:
            if (stdout):
                self.logger.alert(f'Maybe these are configuration profiles:')
            for profile in profiles:
                LocationURI = profile["LocURI"]
                filename = f'profile_{re.sub(r"[^a-zA-Z0-9]", "_", LocationURI)}.txt'
                data = profile["Data"]

                if (write_output_to_dir):
                    write_file(filepath=os.path.join(outdir, "profiles"), filename=filename, content=data)

                if 'WlanXml' in LocationURI or data.strip().startswith('<'):
                    try:
                        data = xmltodict.parse(data)
                        data = json.dumps(data, indent=4)
                    except:
                        pass
                elif data.strip().startswith('{'):
                    try:
                        data = json.dumps(json.loads(data), indent=4)
                    except:
                        pass

                if (stdout):
                    print(f'LocationURI: {LocationURI}')
                    print(Padding(f'{data}', pad=(0, 0, 0, 4)))

        if len(msi_urls):
            self.logger.alert(f'We found line-of-business app...')
            for msi_url in msi_urls:
                self.logger.info(f'Downloading msi file from {msi_url}')
                self.download_msi(msi_url, certpath, keypath)
        
        if odjblob:
            self.logger.success(f'got online domain join blob')
            self.print_djoinblob(odjblob)

        if (write_output_to_dir):
            print(f'Files written to {os.path.join(outdir, "profiles")}')

        # Organise and output the temp sync results 
        # Actions for Replace or Add get stored, deleted does not.
        temp_sync_out = []
        for action in self.checkin_locuri_responses['Replace']:
            temp_sync_out.append(action)
        for action in self.checkin_locuri_responses['Add']:
            temp_sync_out.append(action)

        if (os.path.exists(os.path.join('device_config', self.device_name)) == False):
            os.makedirs(os.path.join('device_config', self.device_name))
        #if (os.path.exists(os.path.join('device_config', self.device_name, 'device_checkin_previous.json'))):
            #with open(os.path.join('device_config', self.device_name, 'device_checkin_previous.json'), 'r') as f:
            #    previous_checkin = json.load(f)
            #for prev_item in previous_checkin:
            #    found = False
            #    for current_item in temp_sync_out:
            #        if prev_item['LocURI'] == current_item['LocURI']:
            #            found = True
            #            break
            #    if found == False:
            #        temp_sync_out.append(prev_item)
        
        write_file(filepath=os.path.join('device_config', self.device_name), filename="device_checkin_previous.json", content=json.dumps(temp_sync_out))

        # If we have the MDM Certpath and keypath, we do not want to remove the files
        if hasattr(self, 'mdm_certpath') and hasattr(self, 'mdm_keypath'):
            self.logger.debug(f'Using existing MDM cert and key files, not removing them...')
            return
        else:
            self.logger.debug(f'Removing temporary MDM cert and key files...')
            os.remove(certpath)
            os.remove(keypath)
            return

    def retire_intune(self):
        access_token, refresh_token = prtauth(
            prt = self.prt, 
            session_key = self.session_key, 
            client_id = clientId["Microsoft Intune Company Portal"], 
            resource = 'https://graph.microsoft.com/', 
            redirect_uri = None, 
            proxy = self.proxy
        )
        self.get_enrollment_info(access_token)

        self.logger.debug(f"resolved IWservice url: {self.spn_IWService}")
        self.logger.debug(f"resolved token renewal url: {self.spn_TokenRenewalService}")

        renewal_token, _ = renew_token(
            refresh_token = refresh_token, 
            client_id = clientId["Microsoft Intune Company Portal"], 
            scope = 'd4ebce55-015a-49b5-a083-c84d1797ae8c/.default openid offline_access profile', 
            proxy = self.proxy
        )

        enrollment_token = token_renewal_for_enrollment(
            url = self.spn_TokenRenewalService, 
            access_token = renewal_token, 
            proxy = self.proxy
        )

        self.get_device_info(self.spn_IWService, enrollment_token)

        retire_info = self.CommonContainer_Retire
        if retire_info == None:
            retire_info = self.CommonContainer_FullWipe
        
        enrollment_type = self.EnrollmentType
        if enrollment_type == 18:
            self.logger.error(f'this device seems to be a corporate device. Ask IT admins to delete this device')
            return

        if retire_info == None:
            self.logger.info(f'maybe this device is not enrolled or already retired')
            return 
        
        
        retire_url = retire_info['target']
        self.logger.info(f"resolved reitrement url: {retire_url}")

        result = self.send_retire_request(retire_url, enrollment_token)
        if result == True:
            self.logger.success(f"successfully retired: {self.deviceid}")
        else:
            self.logger.error(f'failed to retire the device')
        return

    def return_device_information(self):
        access_token, refresh_token = prtauth(
                prt = self.prt, 
                session_key = self.session_key, 
                client_id = clientId["Microsoft Intune Company Portal"], 
                resource = 'https://graph.microsoft.com/', 
                redirect_uri = None, 
                proxy = self.proxy
            )

        self.get_enrollment_info(access_token)
        
        # Obtained from get_enrollment_info
        self.logger.debug(f"IWservice url: {self.spn_IWService}")
        self.logger.debug(f"token renewal url: {self.spn_TokenRenewalService}")

        renewal_token, _ = renew_token(
            refresh_token = refresh_token, 
            client_id = clientId["Microsoft Intune Company Portal"], 
            scope = 'd4ebce55-015a-49b5-a083-c84d1797ae8c/.default openid offline_access profile', 
            proxy = self.proxy
        )

        enrollment_token = token_renewal_for_enrollment(
            url = self.spn_TokenRenewalService, 
            access_token = renewal_token, 
            proxy = self.proxy
        )

        # Obtained from enrollment token
        self.get_device_info(self.spn_IWService, enrollment_token)

        table = Table(title="Device Information")
        table.add_column("Key", justify="left", no_wrap=True)
        table.add_column("Value", justify="left", no_wrap=True)

        table.add_row("Device Official Name", str(self.OfficialName))
        table.add_row("Device Key", str(self.Key))
        table.add_row("Device AadId", str(self.AadId))
        table.add_row("Device HWID", str(self.DeviceHWId))

        table.add_row("Manufacturer", str(self.Manufacturer))
        table.add_row("Model", str(self.Model))
        table.add_row("Operating System", str(self.OperatingSystem))
        table.add_row("OS Version", str(self.OSVersion))
        table.add_row("OS OSSubtype", str(self.OSSubtype))
        table.add_row("Architecture", str(self.Architecture))
        table.add_section()

        table.add_row("Management Type", str(self.ManagementType))
        table.add_row("Management Agent", str(self.ManagementAgent))
        table.add_row("Enrollment Type", str(self.EnrollmentType))

        table.add_section()
        table.add_row("Created Date", str(self.CreatedDate))
        table.add_row("Last Contact", str(self.LastContact))
        table.add_row("Last Contact Notification", str(self.LastContactNotification))
        table.add_row("In Grace Period Until", str(self.InGracePeriodUntilDateTimeUtc))

        table.add_section()
        table.add_row("Compliance State", str(self.ComplianceState))
        table.add_row("Is Compliant In Graph", str(self.IsCompliantInGraph))

        print(table)
        if (self.ComplianceState != 'Compliant' and self.NoncompliantRules):
            secondaryTable = Table(title="Non-compliant Reasons", show_lines=True)
            secondaryTable.add_column("SettingID", justify="left", no_wrap=False,)
            secondaryTable.add_column("Expected Value", justify="left", no_wrap=False)
            secondaryTable.add_column("Reason", justify="left", no_wrap=False)
            secondaryTable.add_column("Details", justify="left", no_wrap=False)
            i = 1
            for reason in self.NoncompliantRules:
                secondaryTable.add_row(
                    f'{reason["SettingID"]}', 
                    f'{reason.get("ExpectedValue", "")}',
                    f'{reason["Title"]}',
                    f'{reason["Description"]}'
                )
                i += 1
            print(secondaryTable)
        
        self.save_device_config()

        return

    # HTTP Request and Response Processing
    def send_retire_request(self, retire_url, access_token):
        response = requests.post(
            url=f"{retire_url}?api-version=16.4&ssp={self.os}SSP&ssp-version={self.ssp_version}&os={self.os}&os-version={self.os_version}&os-sub=None&arch=ARM&mgmt-agent=Mdm",
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=self.proxy,
            verify=False
            )

        if response.status_code == 204:
            return True
        return False

    def get_device_info(self, iwservice_url, access_token):
        # Access Token used is the 
        response = requests.get(
            url=f"{iwservice_url}/Devices?api-version=16.4&ssp={self.os}SSP&ssp-version={self.ssp_version}&os={self.os}&os-version={self.os_version}&os-sub=None&arch=ARM&mgmt-agent=Mdm",
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=self.proxy,
            verify=False
        )
        response_items = None
        
        for item in response.json()['value']:
            if item['AadId'] == self.deviceid:
                response_items = item
                break

        for key in response_items.keys():
            if hasattr(self, key):
                setattr(self, key, response_items[key])
                #print(f'{key}: {response_items[key]}')
            elif hasattr(self, key.replace('.', '_').replace('#', '')):
                setattr(self, key.replace('.', '_'), response_items[key])
                #print(f'{key.replace(".", "_")}: {response_items[key]}')
        return response.json()

    def get_enrollment_info(self, access_token):
        # Retrieve the service principal endpoints for Intune
        # Pre-flight check should be done here to verify if we have already got the attributes needed
        if (hasattr(self, 'spn_IWService')):
            self.logger.debug('Service principal endpoints already resolved, skipping...')
            return

        # Uses the users access token for this auth
        response = requests.get(
            "https://graph.microsoft.com/v1.0/myorganization/servicePrincipals/appId=0000000a-0000-0000-c000-000000000000/endpoints",
            headers={"Authorization": f"Bearer {access_token}"},
            proxies=self.proxy,
            verify=False
        )

        response2 = response.json()
        # For each SPN returned, we set the attribute with a spn_ prefix
        for value in response2['value']:
            setattr(self, f'spn_{value["providerName"]}', value['uri'])
        self.logger.debug('Successfully resolved service principal endpoints')
        return

    # Enrollment Command Processing
    def parse_enroll_response(self, xml_security_token):
        xml = ET.fromstring(xml_security_token)
        certpath = 'characteristic/characteristic/characteristic/characteristic/parm'
        my_cert = xml.findall(certpath)[2].attrib['value']
        return my_cert

    # Extraction and Processing for Checkin commands
    def extract_profiles(self, cmds):
        profiles = []
        if 'Add' not in cmds:
            return profiles
        excluded_keys = ['FakePolicy', 'EntDMID', 'ResetPasswordToken']
        for cmd in cmds['Add']:
            locuri = cmd['Item']['Target']['LocURI']
            is_excluded = False
            for excluded_key in excluded_keys:
                if excluded_key in locuri:
                    is_excluded = True
    
            if is_excluded == False and 'Data' in cmd['Item']:
                    profiles.append({'LocURI': locuri, 'Data':cmd['Item']['Data']})
        return profiles

    def extract_msi_url(self, cmds):
        urls = []
        if 'Exec' not in cmds:
            return urls
        for cmd in cmds['Exec']:
            locuri = cmd['Item']['Target']['LocURI']
            if 'DownloadInstall' in locuri:
                xml = cmd['Item']['Data']
                start = xml.find('<ContentURL>') + len('<ContentURL>')
                end = xml.find('</ContentURL>')
                url = xml[start:end].strip()
                if 'IntuneWindowsAgent.msi' not in url:
                    urls.append(url.replace('&amp;', '&'))
        return urls

    def extract_odjblob(self, cmds):
        if 'Exec' not in cmds:
            return None
        for cmd in cmds['Exec']:
            locuri = cmd['Item']['Target']['LocURI']
            if locuri == './Vendor/MSFT/OfflineDomainJoin/Blob':                    
                return cmd['Item']['Data']
        return None

    def print_djoinblob(self, djoin_encoded):
        djoinblob = base64.b64decode(djoin_encoded)
        
        chars=''
        for b in djoinblob:
            if b == 0:
                continue
            elif 32<= b <= 126:
                chars+=chr(b)
            else:
                chars+=' '
        
        def get_str_and_next(blob, start):
            str_size = (struct.unpack('<I', blob[start:start+0x4])[0]) * 2
            str = blob[start+0xc:start+0xc+str_size].decode('utf-16le')

            next = start+0xc+len(str)*2
            if next % 4 != 0:
                next +=+2

            return str, next

        self.logger.info('parse domain join info...')
        start = 0xc0
        domain, next = get_str_and_next(djoinblob, start)
        computername, next = get_str_and_next(djoinblob, next)
        password, next = get_str_and_next(djoinblob, next)
        dcip = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b').findall(chars)

        print(f' - domain: {domain}')
        print(f' - computername: {computername}$')
        print(f' - computerpass: {password}')
        print(f' - dc ip address: {dcip[0]}')

        return    

    def download_msi(self, msi_url, certpath, keypath):
        parsed_url = urllib.parse.urlparse(msi_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        file_name_hash = query_params.get('fileNameHash', [None])[0]

        response = requests.get(
            url=msi_url,
            cert=(certpath, keypath),
            )
        
        if response.status_code == 200 and file_name_hash:
            filename = os.path.splitext(file_name_hash)[0]
            write_file(filepath=os.path.join(outdir, "apps"), filename=filename, content=response.content)
            self.logger.success(f'Successfully downloaded to {filename}')
        else:
            self.logger.error(f'Failed to download msi file')

    # SyncML Command Processing
    def send_syncml(self, data, certpath, keypath):
        response = requests.post(
            url=self.checkin_url,
            data=data,
            headers={'User-Agent': f'MSFT {self.os} OMA DM Client/2.7' , 'Content-Type': 'application/vnd.syncml.dm+xml'},
            verify=False,
            cert=(certpath, keypath)
            )
        return response.content

    def generate_syncml_header(self, msgid, sessionid, imei):
        syncml_template = {
            "SyncML": {
                "@xmlns": "SYNCML:SYNCML1.2",
                "SyncHdr": {
                    "VerDTD": "1.2",
                    "VerProto": "DM/1.2",
                    "SessionID": f"{str(sessionid)}",
                    "MsgID": f"{str(msgid)}",
                    "Target": {
                        "LocURI": self.checkin_url
                    },
                    "Source": {"LocURI": f"imei:{imei}"}
                },
                "SyncBody": {}
                }
            }
        return syncml_template

    def generate_syncml_response(self, msgid, sessionid, imei, cmds):
        # Incoming cmds are structured as a dictionary of command types, each containing a list of commands
        syncml_data = self.generate_syncml_header(msgid, sessionid, imei)
        msgref = msgid - 1
        syncml_data["SyncML"]["SyncBody"] = {
            "Status": [
                {
                    "CmdID": "1",
                    "MsgRef": str(msgref),
                    "CmdRef": "0",
                    "Cmd": "SyncHdr",
                    "Data": "200",
                },
                {
                    "CmdID": "3",
                    "MsgRef": str(msgref),
                    "CmdRef": "1",
                    "Cmd": "Status",
                    "Data": "200",
                }
            ],
            "Results":[],
            "Final": None,
            }

        cmdid = 8

        out_cmds = {'Get':[], 'Atomic':[], 'Add':[], 'Replace':[], 'Exec':[], 'Sequence':[], 'Delete':[]}

        # Process each command in cmds
        for cmd_type in cmds:
            for cmd in cmds[cmd_type]:
                out_cmds[cmd_type].append(cmd)
                # This is our status response for each command
                status = {
                    "CmdID": str(cmdid),
                    "MsgRef": str(msgref),
                    "CmdRef": cmd["CmdID"],
                    "Cmd": cmd_type,
                    "Data": "200"
                }

                # If the command is a GET
                if cmd_type == 'Get':
                    locuri = cmd["Item"]["Target"]["LocURI"]
                    
                    #self.logger.info(f'LocURI: {locuri}')

                    result, data = self.get_temp_sync_results(locuri)
                    #if (result == True) and (data is None):
                        #print("Deleted Result found, sending 404")
                    #if data is not None:
                        #print(f'Found temp sync result for {locuri}')
                    if result == False:
                        # This does a lookup to the devices get_syncml_data function to retrieve data for the given LocURI
                        # If we have got a response for that LocURI in our devices config, send that response
                        data = self.get_syncml_data(locuri)
                    if data:
                        #if (locuri == './DevInfo/Mod'):
                        #    print(f'Model data being sent: {data["Data"]}')
                        self.logger.debug(f'sending data for {locuri}')
                        #print(f'Sending data for {locuri}')
                        #print(f'Data: {data}')

                        result = {
                            "CmdID": str(cmdid+1),
                            "MsgRef": str(msgref),
                            "CmdRef": cmd["CmdID"],
                            "Item": {
                                "Source": {
                                    "LocURI": locuri
                                    },
                                "Meta": {
                                    "Format": {"@xmlns": "syncml:metinf", "#text": data["Format"]}
                                },
                                "Data": data["Data"],
                                }
                            }
                        syncml_data["SyncML"]["SyncBody"]["Results"].append(result)
                    # Else if we do not have a response for that locuri, return 404
                    else:
                        status["Data"] = "404"
                        self.logger.debug(f'no data found for {locuri}')
                    
                    cmdid += 2

                # Documentation on the schema is found in https://www.openmobilealliance.org/release/Common/V1_2_2-20090724-A/OMA-TS-SyncML-RepPro-V1_2_2-20090724-A.pdf
                # Section 6.5 - Protocol Command Elements

                # Multiple other command types were found:
                # Atomic
                # Delete
                # Sequence
                # Get
                # Replace
                # Add

                # 6.5.3 Atomic
                # Usage: Specifies the SyncML command to request that the subordinate commands be executed as a set or not at all
                # 
                # 6.5.5 Delete
                # Usage: Specifies the SyncML command to delete data from a data collection.
                # 
                # 6.5.15 Sequence
                # Usage: Specifies the SyncML command to order the processing of a set of SyncML commands.
                # 
                # 6.5.7 Get
                # Usage: Specifies the SyncML command to retrieve data from the recipient.
                # 
                # 6.5.12 Replace
                # Usage: Specifies the SyncML command to replace data.
                # 
                # 6.5.1 Add
                # Usage: Specifies the SyncML command to add data to a data collection.

                elif cmd_type == 'Add':
                    locuri = cmd["Item"]["Target"]["LocURI"]
                    self.logger.debug(f'received Add for {locuri}')
                    # Store the added locuri in our checkin_locuri_responses for temporary sync result tracking, along with the new data
                    data = cmd["Item"].get("Data", None)
                    meta = cmd["Item"].get("Meta", None)
                    if meta and "Format" in meta:
                        format_type = meta["Format"]["#text"]
                        self.checkin_locuri_responses["Add"].append({locuri: {"Data": data, "Format": format_type}})
                    else:
                        self.checkin_locuri_responses["Add"].append({locuri: {"Data": data, "Format": "chr"}})

                elif cmd_type == 'Delete':
                    locuri = cmd["Item"]["Target"]["LocURI"]
                    self.logger.debug(f'received Delete for {locuri}')
                    # Store the deleted locuri in our checkin_locuri_responses for temporary sync result tracking
                    self.checkin_locuri_responses["Delete"].append(locuri)
                    cmdid += 1

                elif cmd_type == 'Replace':
                    locuri = cmd["Item"]["Target"]["LocURI"]
                    self.logger.debug(f'received Replace for {locuri}')
                    # Store the replaced locuri in our checkin_locuri_responses for temporary sync result tracking, along with the new data
                    data = cmd["Item"].get("Data", None)
                    meta = cmd["Item"].get("Meta", None)
                    if meta and "Format" in meta:
                        format_type = meta["Format"]["#text"]
                        self.checkin_locuri_responses["Replace"].append({locuri: {"Data": data, "Format": format_type}})
                    else:
                        self.checkin_locuri_responses["Replace"].append({locuri: {"Data": data, "Format": "chr"}})
                    cmdid += 1

                # For other command types, pass
                else:
                    cmdid += 1

                # Append the resulting status for each command to the SyncBody
                syncml_data["SyncML"]["SyncBody"]["Status"].append(status)


        if (os.path.exists(os.path.join(outdir, f'out_cmds.json'))):
            #print("Appending to existing out_cmds.json")
            existing_cmds = os.path.join(outdir, f'out_cmds.json')
            with open(existing_cmds, 'r', encoding='utf-8') as f:
                existing_cmds_raw = json.load(f)

            for cmd_type in out_cmds:
                for cmd in out_cmds[cmd_type]:
                    existing_cmds_raw[cmd_type].append(cmd)

            write_file(filepath=os.path.join(outdir), filename=f'out_cmds.json', content=json.dumps(existing_cmds_raw))
        else:
            #print("overwriting out_cmds.json")
            write_file(filepath=os.path.join(outdir), filename="out_cmds.json", content=json.dumps(out_cmds))

        #print(self.checkin_locuri_responses)

        return xmltodict.unparse(syncml_data, pretty=False)
    
    # I am probabily going to redo this part at some stage... 
    def get_temp_sync_results(self, locuri):
        # During the sync process, we can add, replace, or delete certain values from nodes, this is meant to be our frontrunner if we have had a modified value during the sync process

        if locuri in [list(item.keys())[0] for item in self.checkin_locuri_responses["Replace"]]:
            for item in self.checkin_locuri_responses["Replace"]:
                if locuri in item:
                    #print(f'Returning replaced data for {locuri}')
                    #print(item)
                    #f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/ExchangeID": {
                    #    "Format": "chr",
                    #    "Data": self.uid
                    #},
                    return True, {"Format": item[locuri]["Format"], "Data": item[locuri]["Data"]}

        elif locuri in [list(item.keys())[0] for item in self.checkin_locuri_responses["Add"]]:
            for item in self.checkin_locuri_responses["Add"]:
                if locuri in item:
                    #print(f'Returning added data for {locuri}')
                    #print(item)
                    #return True, {"Data": item[locuri]["Data"], "Format": item[locuri]["Format"]}
                    return True, {"Format": item[locuri]["Format"], "Data": item[locuri]["Data"]}

        # If the value is deleted, we want to return 2 values, one of the bool that it was found, and another of None since it was deleted and will have no data
        if locuri in self.checkin_locuri_responses["Delete"]:
            return True, None
        else:
            return False, None

    def load_old_syncml_results(self):
        previous_checkin_path = os.path.join('device_config', self.device_name, 'device_checkin_previous.json')
        if (os.path.exists(previous_checkin_path) == False):
            return

        with open(previous_checkin_path, 'r', encoding='utf-8') as f:
            previous_checkin = json.load(f)

        #{
        #    "./Vendor/MSFT/PassportForWork/Biometrics/FacialFeaturesUseEnhancedAntiSpoofing": {
        #        "Data": "true",
        #        "Format": "bool"
        #    }
        #},

        for item in previous_checkin:
            locuri = list(item.keys())[0]
            data = item[locuri].get('Data', None)
            format_type = item[locuri].get('Format', 'chr')
            #print(f"LocURI: {locuri}\nData: {data}\nFormat: {format_type}")
            if data is None:
                self.checkin_locuri_responses["Delete"].append(locuri)
            else:
                self.checkin_locuri_responses["Replace"].append({locuri: {"Data": data, "Format": format_type}})

        #print(previous_checkin)

        #for item in previous_checkin:
        #    locuri = item
        #    data = item.get('Data', None)
        #    format_type = item.get('Format', 'chr')
        #    if data is None:
        #        self.checkin_locuri_responses["Delete"].append(locuri)
        #    else:
        #        self.checkin_locuri_responses["Replace"].append({locuri: {"Data": data, "Format": format_type}})


        return

    def fix_replace_cmds(self):
        commands = os.path.join(os.path.join(outdir), 'replace_cmds3.json')
        with open(commands, 'r', encoding='utf-8') as f:
            commands_raw = json.load(f)
        
        out = []

        for cmds in commands_raw:

            locuri = cmds['Target']['LocURI']
            # Verify if the locuri exists in our out array
            if not any(d['Target']['LocURI'] == locuri for d in out):
                out.append(cmds)
            else:
                # If the entry exists, add only keys not found in the existing entry
                for existing in out:
                    if existing['Target']['LocURI'] == locuri:
                        for key in cmds.keys():
                            if key not in existing:
                                print(f'adding missing key {key} to existing locuri {locuri}')
                                existing[key] = cmds[key]

        write_file(filepath=os.path.join(outdir), filename="replace_cmds_fixed.json", content=json.dumps(out, indent=4))

    def parse_syncml(self, xml_data):
        #print(xml_data)
        parsed_dict = xmltodict.parse(xml_data)
        syncml_data = parsed_dict['SyncML']
        sync_body = syncml_data['SyncBody']
        results = {'Get':[], 'Atomic':[], 'Add':[], 'Replace':[], 'Exec':[], 'Sequence':[], 'Delete':[]}
        results = self.parse_omadm_cmd(sync_body, results)

        cmdlen = 0
        for omadm_cmd in results.keys():
            cmdlen += len(results[omadm_cmd])

        if cmdlen == 0:
            return None
        else:
            return results

    def parse_omadm_cmd(self, input, results):
        for omadm_cmd in results.keys():
            if omadm_cmd in input:
                if omadm_cmd == 'Atomic' or omadm_cmd == 'Sequence':
                    if isinstance(input[omadm_cmd], list):
                        for multicmd in input[omadm_cmd]:
                            results[omadm_cmd].append({"CmdID": multicmd['CmdID']})
                            results = self.parse_omadm_cmd(multicmd, results)
                    else:
                        results[omadm_cmd].append({"CmdID": input[omadm_cmd]['CmdID']})
                        results = self.parse_omadm_cmd(input[omadm_cmd], results)
                else:
                    if isinstance(input[omadm_cmd], list):
                        results[omadm_cmd].extend(input[omadm_cmd])
                    else:
                        results[omadm_cmd].append(input[omadm_cmd])
        return results

    # CSR and Certificate Processing
    def create_csr(self, private_key, cname):
        csr_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cname)
        ])

        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(csr_subject)
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())
        der_csr = csr.public_bytes(encoding=serialization.Encoding.DER)
        return der_csr

    def save_mdm_certs(self, private_key, my_cert, pfxpath):
        cert = x509.load_der_x509_certificate(base64.b64decode(my_cert), default_backend())
        pfx = serialization.pkcs12.serialize_key_and_certificates(
            pfxpath.encode('utf-8'),
            private_key,
            cert,
            None,
            serialization.BestAvailableEncryption(b"password")
            )

        with open(pfxpath, 'wb') as outfile:
            outfile.write(pfx)

        return

    @abstractmethod
    def generate_initial_syncml(self, sessionid, imei):
        pass

    @abstractmethod
    def get_enrollment_token(self, refresh_token):
        pass

    @abstractmethod
    def send_enroll_request(self, enrollment_url, access_token_b64, csr_pem, ztdregistrationid):
        pass

    @abstractmethod
    def get_syncml_data(self, key):
        pass

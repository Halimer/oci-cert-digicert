import oci
import time
import datetime
import pytz
import os
import requests
from requests.exceptions import HTTPError


def error_wrapper(func):
    def error_handler(*args, **kwargs):
        try:
            func(*args, **kwargs)
        
        except Exception as e:
            raise RuntimeError(f'Error in {func.__name__}:  + {str(e.args)}')
    return error_handler
##########################################################################
# Create signer for Authentication
# Input - config_profile and is_instance_principals and is_delegation_token
# Output - config and signer objects
##########################################################################
def create_signer(file_location, config_profile, is_instance_principals, is_delegation_token, is_security_token):

    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            print("Error obtaining instance principals certificate, aborting")
            raise SystemExit

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                print(
                    "*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                raise SystemExit

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
                    delegation_token=delegation_token)

                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
            raise SystemExit

        except Exception:
            raise
    # ---------------------------------------------------------------------------
    # Security Token - Credit to Dave Knot (https://github.com/dns-prefetch)
    # ---------------------------------------------------------------------------
    elif is_security_token:

        try:
            # Read the token file from the security_token_file parameter of the .config file
            config = oci.config.from_file(
                oci.config.DEFAULT_LOCATION,
                (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
            )

            token_file = config['security_token_file']
            token = None
            with open(token_file, 'r') as f:
                token = f.read()

            # Read the private key specified by the .config file.
            private_key = oci.signer.load_private_key_from_file(config['key_file'])

            signer = oci.auth.signers.SecurityTokenSigner(token, private_key)

            return config, signer

        except KeyError:
            print("* Key Error obtaining security_token_file")
            raise SystemExit

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:

        try:
            config = oci.config.from_file(
                file_location if file_location else oci.config.DEFAULT_LOCATION,
                (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
            )
            signer = oci.signer.Signer(
                tenancy=config["tenancy"],
                user=config["user"],
                fingerprint=config["fingerprint"],
                private_key_file_location=config.get("key_file"),
                pass_phrase=oci.config.get_config_value_or_default(
                    config, "pass_phrase"),
                private_key_content=config.get("key_content")
            )
            return config, signer
        except Exception:
            print(
                f'** OCI Config was not found here : {oci.config.DEFAULT_LOCATION} or env varibles missing, aborting **')
            raise SystemExit


class DigiCertTLM:

    def __init__(self,tag_name='DigiCertTLM'):
       self.__digicert_tlm_server = os.environ.get('DigiCertTLMServer')
       self.__digicert_tlm_api_key = os.environ.get('DigiCertTLMAPIKey')
       self.__oci_tag_name = tag_name
       self.__digicert_tlm_url = self.__digicert_tlm_server + "/mpki/api/v1/certificate-search"
       self.__tlm_certificates = []
    
    def get_certificates_from_tlm(self):
        if self.__tlm_certificates:
            return self.__tlm_certificates
        else:
            return self.__query_certificates_from_tlm()
    
    def get_get_oci_tag_name(self):
        return self.__oci_tag_name

    def __query_certificates_from_tlm(self):
        headers = { 
            'x-api-key' : self.__digicert_tlm_api_key,
            'limit' : '2'
        }
        try:
            response = requests.request("GET",self.__digicert_tlm_url, headers=headers,data={})
            response.raise_for_status()
            # access JSON content
            jsonResponse = response.json()

            for seat in jsonResponse['items']:
                self.__tlm_certificates.append(seat)
            return self.__tlm_certificates
        except HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
        except Exception as err:
            print(f'Other error occurred: {err}')


class OCICertificates:
    def __init__(self, config, signer, day_to_expiry=30):
        self.__oci_certificates = []
        self.__oci_certificates_near_expiration = []
        self.__cert_key_time_max_datetime = start_datetime + datetime.timedelta(days=day_to_expiry)
        self.__regions = {}
        self.__config = config
        self.__signer = signer
        self.__create_regional_signers("")
        self.__certificates_read_certificates()
        self.__find_oci_certificates_near_expiration()

    ##########################################################################
    # Create regional config, signers adds appends them to self.__regions object
    ##########################################################################
    def __create_regional_signers(self, proxy):
        print("Creating regional signers and configs...")
        try:

            self.__identity = oci.identity.IdentityClient(
                self.__config, signer=self.__signer)
            if proxy:
                self.__identity.base_client.session.proxies = {'https': proxy}

            # Getting Tenancy Data and Region data
            self.__tenancy = self.__identity.get_tenancy(
                config["tenancy"]).data
            regions = self.__identity.list_region_subscriptions(
                self.__tenancy.id).data
            for region in regions:
                record = oci.util.to_dict(region)
                self.__regions[record['region_name']] = record

        except Exception as e:
            raise RuntimeError("Failed to get identity information." + str(e.args))
        
        for region_key, region_values in self.__regions.items():
            # Creating regional configs and signers
            region_signer = self.__signer
            region_signer.region_name = region_key
            region_config = self.__config
            region_config['region'] = region_key

            try:
                search = oci.resource_search.ResourceSearchClient(region_config, signer=region_signer)
                if proxy:
                    search.base_client.session.proxies = {'https': proxy}
                region_values['search_client'] = search

                certificate_client = oci.certificates_management.CertificatesManagementClient(region_config, signer=region_signer)
                if proxy:
                    search.base_client.session.proxies = {'https': proxy}
                region_values['certificate_client'] = certificate_client                    


            except Exception as e:
                self.__errors.append({"id" : "__create_regional_signers", "error" : str(e)})
                raise RuntimeError("Failed to create regional clients for data collection: " + str(e))

    ##########################################################################
    # Query All certificates in the tenancy
    ##########################################################################
    def __certificates_read_certificates(self):
        for region_key, region_values in self.__regions.items():
            certificates_data = oci.pagination.list_call_get_all_results(
                    region_values['search_client'].search_resources,
                    search_details=oci.resource_search.models.StructuredSearchDetails(
                        query="query certificate resources return allAdditionalFields")
                ).data
            cert_compartments = {}

            for certificate in certificates_data:
                cert_compartments[certificate.compartment_id] = certificate.compartment_id

            for compartment in cert_compartments:
                certs = oci.pagination.list_call_get_all_results(
                    region_values['certificate_client'].list_certificates,
                    compartment_id=compartment).data
                for cert in certs:
                    record = oci.util.to_dict(cert)
                    self.__oci_certificates.append(cert)
        print(f"Found a total of {len(self.__oci_certificates)} in OCI")


    def __find_oci_certificates_near_expiration(self):
        for cert in self.__oci_certificates:
            if cert.current_version_summary.validity and cert.current_version_summary.validity.time_of_validity_not_after <= self.__cert_key_time_max_datetime:
                    self.__oci_certificates_near_expiration.append(cert)
        print(f"Found {len(self.__oci_certificates_near_expiration)} OCI Certificates near expiry ")
    
    ##########################################################################
    # Return All certificates in the tenancy
    ##########################################################################
    def get_oci_certificates(self):
        return self.__oci_certificates

    ##########################################################################
    # Return All certificates in the tenancy near expiry
    ##########################################################################
    def get_oci_certificates_near_expiration(self):
        return self.__oci_certificates_near_expiration
    
    ##########################################################################
    # Return All certificates in the tenancy near expiry
    ##########################################################################
    def add_new_oci_imported_certificate(self, compartment_id, name, cert_chain, certificate_pem, private_key_pem):
        new_cert = oci.certificates_management.models.CreateCertificateByImportingConfigDetails(
            
            cert_chain_pem=cert_chain,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem)
                 
        # fu = oci.certificates_management.models.CreateCertificateDetails(
        #     create_certificate_details=new_cert
        # )
        response = self.__regions['us-ashburn-1']['certificate_client'].create_certificate(
            oci.certificates_management.models.CreateCertificateDetails(
                compartment_id=compartment_id,
                name=name,
                certificate_config=new_cert
                ))

        
        print(response.data)
        return response



start_time = time.time()
start_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)

# tlm_certs = DigiCertTLM()
# tlm_managed_certs = tlm_certs.get_certificates_from_tlm()

config, signer = create_signer("","ociateam",False,False,False)

oci_certs = OCICertificates(config=config, signer=signer)
# oci_managed_certs = oci_certs.get_oci_certificates()
# oci_certificates_near_expiration = oci_certs.get_oci_certificates_near_expiration()
oci_certs.add_new_oci_imported_certificate(
    name="testing",
    compartment_id="ocid1.compartment.oc1..aaaaaaaawlfypwpntj6ftt3kk2jacwbzyuv6tepfmbdwimizkkqo4s5xw25q",
    cert_chain=cert_chain,
    certificate_pem=cert_pem,
    private_key_pem=private_pem
)

# for cert in oci_managed_certs:
#     print(cert.name)

# for cert in tlm_managed_certs:
#     for oci_cert in oci_certificates_near_expiration:
#         if oci_cert.freeform_tags and tlm_certs.get_get_oci_tag_name() in oci_cert.freeform_tags:
#             print(f'This OCI is managed in TLM.  The TLM serial number is: {oci_cert.freeform_tags[tlm_certs.get_get_oci_tag_name()]}')


oci_certs.add_new_oci_certificate_bundle(compartment_id="ocid1.compartment.oc1..aaaaaaaawlfypwpntj6ftt3kk2jacwbzyuv6tepfmbdwimizkkqo4s5xw25q", 
                                         name="HelloOCI")

print("--- %s seconds ---" % (time.time() - start_time))

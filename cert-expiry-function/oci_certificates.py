import oci
import time
import datetime
import pytz
import os
import requests
from requests.exceptions import HTTPError
from copy import copy

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
    def __init__(self, config, signer, days_to_expiry=30):
        self.__cert_url = "https://cloud.oracle.com/security/certificates/certificate/"
        self.__oci_certificates = []
        self.__oci_certificates_near_expiration = []
        self.__start_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)
        self.__cert_key_time_max_datetime = self.__start_datetime + datetime.timedelta(days=days_to_expiry)
        self.__regions = {}
        self.__config = copy(config)
        self.__signer = copy(signer)
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
                self.__config["tenancy"]).data
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
        try:
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
                        self.__oci_certificates.append(cert)
        except Exception as e:
            pass
        print(f"Found a total of {len(self.__oci_certificates)} in OCI")

    def __find_oci_certificates_near_expiration(self):
        for cert in self.__oci_certificates:
            if cert.current_version_summary.validity and cert.current_version_summary.validity.time_of_validity_not_after <= self.__cert_key_time_max_datetime:
                    region_id = cert.id.split(".")[3]
                    region_name = self.__get_region_name_from_key(region_id)
                    self.__oci_certificates_near_expiration.append(self.__cert_url + cert.id + "?region=" + region_name)


    def get_oci_certificates_with_cname(self, cname):
        results = []
        for cert in self.__oci_certificates:
            if cert.subject:
                if cname == cert.subject.common_name:
                    results.append(oci.util.to_dict(cert))

        print(f"Found {len(results)} with cname {cname}")
        return results    
    

    ##########################################################################
    # Returns a region name for a region key
    # Takes: region key
    ##########################################################################
    def __get_region_name_from_key(self, region_key):
        for key, region_values in self.__regions.items():
            if region_values['region_key'].upper() == region_key.upper() or region_values['region_name'].upper() == region_key.upper(): 
                return region_values['region_name']


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
    # Return new certificate data 
    # Takes: Add new certificate takes, region, comp,name and cert details
    # The read_certificates_files provides a JSON with the 3 required fields
    ##########################################################################
    def add_new_oci_imported_certificate(self, name, compartment_id, region, cert_chain, certificate_pem, private_key_pem):
        new_cert = oci.certificates_management.models.CreateCertificateByImportingConfigDetails(
            cert_chain_pem=cert_chain,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem)
                 
        response = self.__regions[region]['certificate_client'].create_certificate(
            oci.certificates_management.models.CreateCertificateDetails(
                compartment_id=compartment_id,
                name=name,
                certificate_config=new_cert
                ))       
        return response.data
    
    ##########################################################################
    # Update certificate takes, certificate id and cert details
    ##########################################################################
    def update_oci_imported_certificate(self, certificate_id, region, cert_chain, certificate_pem, private_key_pem):
        updated_cert = oci.certificates_management.models.UpdateCertificateByImportingConfigDetails(
            cert_chain_pem=cert_chain,
            certificate_pem=certificate_pem,
            private_key_pem=private_key_pem)
                 
        response = self.__regions[region]['certificate_client'].update_certificate(
                certificate_id=certificate_id,
                update_certificate_details=oci.certificates_management.models.UpdateCertificateDetails(
                certificate_config=updated_cert))       
        
        return response.data


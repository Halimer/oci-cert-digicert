import oci
import time
import datetime
import pytz

start_time = time.time()
start_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)
_DAYS_OLD = 30

# config = oci.config.from_file()
config = oci.config.from_file()

search_client = oci.resource_search.ResourceSearchClient(config)

certificate_client = oci.certificates_management.CertificatesManagementClient(config)

identity_client = oci.identity.IdentityClient(config)

query_all_resources = "query all resources"
# resources_in_root_data = self.__search_run_structured_query(query)

regions = ['us-ashburn-1', 'us-phoenix-1']

# all_resources_json = {}

# all_resource_search = oci.pagination.list_call_get_all_results(
#     search_client.list_resource_types).data

cert_key_time_max_datetime = start_datetime + datetime.timedelta(days=_DAYS_OLD)
print(cert_key_time_max_datetime)
certificate_query = f"query certificate resources return allAdditionalFields"

certificates = oci.pagination.list_call_get_all_results(
    search_client.search_resources,
    search_details=oci.resource_search.models.StructuredSearchDetails(
        query=certificate_query)
).data
all_certificates = []
cert_compartments = {}

for certificate in certificates:
    cert_compartments[certificate.compartment_id] = certificate.compartment_id

for compartment in cert_compartments:
    print(compartment)
    certs = oci.pagination.list_call_get_all_results(
        certificate_client.list_certificates,
        compartment_id=compartment).data
    for cert in certs:
        record = oci.util.to_dict(cert)
        all_certificates.append(cert)

for cert in all_certificates:
  if cert.current_version_summary.validity and cert.current_version_summary.validity.time_of_validity_not_after <= cert_key_time_max_datetime:
        print(cert.name)
        print(cert.current_version_summary.validity.time_of_validity_not_after)



print("--- %s seconds ---" % (time.time() - start_time))

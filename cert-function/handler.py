import time
import datetime
import pytz
import oci
from read_certificate_files import Certificate_Files
from oci_certificates import OCICertificates
import argparse

start_time = time.time()
start_datetime = datetime.datetime.now().replace(tzinfo=pytz.UTC)


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



##########################################################################
# Input: Command line arguments
# Action : Set arguments and stores arguments
# Returns: Command line arguments list
##########################################################################
def get_parser_arguments():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--release',
        required=True,

        dest='release',
        help="Release Directory to CSV file for comparison"
    )
    parser.add_argument(
        '--issue',
        dest='issue',
        required=True,
        help="Issue  CSV file for comparison")
    parser.add_argument(
        '--config',
        dest='config',
        required=True,
        help="OCI Config file to run through")
    
    parser.add_argument(
        '--collect_only',
        action='store_true', 
        default=False,
        help="Collect Data but don't compare")
    
    result = parser.parse_args()
    print(len(sys.argv))

    if len(sys.argv) < 7:
        parser.print_help()
        exit()

    print(result.collect_only)

    return result.release,result.issue,result.config,result.collect_only


config, signer = create_signer("","",False,False,False)

oci_certs = OCICertificates(config=config, signer=signer)
oci_managed_certs = oci_certs.get_oci_certificates()
oci_cname = oci_certs.get_oci_certificates_with_cname("www.gnlmnm.com")
print(oci_cname)
oci_certificates_near_expiration = oci_certs.get_oci_certificates_near_expiration()
print(oci_certificates_near_expiration)


exit()

certificates_files = Certificate_Files()
certificate_json = certificates_files.get_certificates(directory='/Users/hammer/Documents/GitHub/oci-cert-digicert/cert-function/')
print(certificate_json)
# response = oci_certs.add_new_oci_imported_certificate(
#     name="testing4",
#     compartment_id="ocid1.compartment.oc1..aaaaaaaawlfypwpntj6ftt3kk2jacwbzyuv6tepfmbdwimizkkqo4s5xw25q",
#     region="us-ashburn-1",
#     cert_chain=certificate_json['cert_chain'],
#     certificate_pem=certificate_json['certificate_pem'],
#     private_key_pem=certificate_json['private_key_pem']
# )
# print("*" * 80)
# print(response)
# print("*" * 80)
# certificate_id = 'ocid1.certificate.oc1.iad.amaaaaaac3adhhqasr5p5a3h4ita3ykc5bhrcz2xtiyklzpxwzv42kzqc3ea'

# response = oci_certs.update_oci_imported_certificate(
#     certificate_id=certificate_id,
#     region="us-ashburn-1",
#     cert_chain=certificate_json['cert_chain'],
#     certificate_pem=certificate_json['certificate_pem'],
#     private_key_pem=certificate_json['private_key_pem']
# )
# print("*" * 80)
# print(response)
# print("*" * 80)


print("--- %s seconds ---" % (time.time() - start_time))

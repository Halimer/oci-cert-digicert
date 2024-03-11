import io
import json
import os
import logging
from fdk import response
import time
import datetime
import pytz
import oci
from oci_certificates import OCICertificates
from oci_topic import publish_message_to_topic

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



def handler(ctx, data: io.BytesIO=None):

    try:
        # Getting Functions Environment Variables TOPIC OCID is rquired
        ctx_data = dict(ctx.Config())
        try:
            DAYS_TO_EXPIRY = int(ctx_data['DAYS_TO_EXPIRY'])
        except:
            DAYS_TO_EXPIRY = 30 
        TOPIC_OCID = ctx_data['TOPIC_OCID']

    except (Exception, ValueError) as ex:
        logging.error('Error failed to get TOPIC OCID: ' + str(ex))
        raise

    try:
        config, signer = create_signer("./.config","ociateam",False,False,False)
        oci_certs = OCICertificates(config=config, signer=signer, days_to_expiry=DAYS_TO_EXPIRY)
        oci_managed_certs = oci_certs.get_oci_certificates()
        expiring_certs = oci_certs.get_oci_certificates_near_expiration()
        
        oci_cname = oci_certs.get_oci_certificates_with_cname("www.gnlmnm.com")
        logging.debug(oci_cname)
        logging.debug(expiring_certs)
    except Exception as e:
        
        logging.ERROR("Failed to get expiring certifications with error: " + str(e))
        raise

    message_text = str(len(expiring_certs)) + " certificates near expiration.\n"
    for cert in expiring_certs:
        message_text += cert + "\n"
    logging.debug(message_text)
    
    topic_message = publish_message_to_topic(config=config, signer=signer,
                             topic_id=TOPIC_OCID, message=message_text)
    logging.debug(topic_message)
    return response.Response(
        ctx, response_data=json.dumps(
            {"message": "{0} Certificates near expiry".format(len(expiring_certs))}),
        headers={"Content-Type": "application/json"}
    )


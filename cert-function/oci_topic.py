import oci

def create_notification_client(config, signer):
    try:
        return oci.ons.NotificationDataPlaneClient(config=config,signer=signer)
    except Exception as e:
        print("Error creating notification client: " + str(e))
        raise

def publish_message_to_topic(config, signer, topic_id, message):
    try:
        topic_client = create_notification_client(config=config, signer=signer)
        topic_message = oci.ons.models.MessageDetails(
            body=message,
            title="Expired Certificates"
        )
        topic_client.publish_message(topic_id=topic_id,
                                     message_details=topic_message)
        return {"Status" : "Success", "Message" : ""}
    except Exception as e:
        return {"Status" : "Error", "Message" : str(e)}
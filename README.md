# oci-cert-digicert
OCI Certificate managed with DigiCert


## Expired Certificates Function

### Overview
This function when triggered searches all regions in a tenancy for certificates nearing expiration.  The default is set to those certificates expiring within 30 days.

### Architecture
![](images\Certificate-Expiry-Function.png)

### Prerequisites

#### OCI Permissions
Below is an example of on OCI policy that grants the permissions required to preform the below tasks in this README.md.
```
# Needed to Create and deploy functions
allow group <group-name> to read objectstorage-namespaces in tenancy
allow group <group-name> to inspect compartments in tenancy
allow group <group-name> to read logging-family in tenancy
allow group <group-name>to read repos in tenancy
allow group <group-name>to manage repos in tenancy where target.repo.name = '/<repo-name>-/'
# Needed to create the Event Rule at the tenancy level
allow group <group-name>to manage cloudevents-rules in tenancy
allow group <group-name>to manage functions-family in compartment <splunk_comp_name>
Allow group <group-name> to use apm-domains in compartment  <splunk_comp_name>
Allow group <group-name> to use virtual-network-family in compartment <compartment-name>
Allow group <group-name> to read metrics in compartment <compartment-name>
Allow group <group-name> to manage functions-family in compartment <compartment-name>
Allow group <group-name> to read metrics in compartment <compartment-name>
Allow group <group-name> to manage logging-family in compartment <compartment-name>
Allow group <group-name> to use virtual-network-family in compartment <compartment-name>
```

Before you deploy this sample function, make sure you have run steps A, B, C 
and C of the [Oracle Functions Quick Start Guide for Cloud Shell](https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsquickstartcloudshell.htm)
#### A - Set up your tenancy
#### B - Create application
#### C - Set up your Cloud Shell dev environment
#### List Applications 

After you have successfully completed the prerequisites, you should see your 
application in the list of applications.

```
fn ls apps
```

#### Create Topic for Messages
1. From the navigation menu, select **Notifications** 
1. Select your Compartment
1. Click **Create Topic**
    1. Enter a **Topic Name**
    1. Enter a **Description**
    1. Click **Create**
1. Select the newly created Topic
1. Click **Create Subscription**
    1. Select your **Protocol**
    1. Enter additional attributes required for your protocol selected
    1. Click **Create**
1. Copy the OCID ex. `ocid1.onstopic.oc1.iad....`

### Review and customize the function

Review the following files in the current folder:
* Function code, 
    * [func.py](./cert-expiry-function/func.py)
    * [oci_certificates.py](./cert-expiry-function/oci_certificates.py)
    * [oci_topics.py](./cert-expiry-function/oci_topics.py)
* Function dependencies, [requirements.txt](./requirements.txt)
* Function metadata, [func.yaml](./func.yaml) - In this file set the TOPIC_OCID to the to `OCID` you copied from the Custom Log
    * ex: `TOPIC_OCID: ocid1.onstopic.oc1.iad.....`

### Deploy the function

* In Cloud Shell, create the oci function by runing the `fn init --runtime python <function-name>` this will create a generic function in a directory called `<function-name>`
* Drag the `func.py` and `requirements.txt` into Cloud Shell. This will put them in the home directory
* Go into the function directory`cd <function-name>`
* Remove the existing `func.py` and `requirements.txt` by running `rm func.py requirements.txt`
* Copy the code into the function directory by running 
```
cp ~/func.py .
cp ~/requirements.py
```
* Now run `fn deploy` command to build *this* function and its dependencies as a Docker image, push the image to the specified Docker registry, and deploy *this* function to Oracle Functions 
in the application created earlier:

```
fn -v deploy --app <app-name>
```
e.g.,
```
fn -v deploy --app myapp
```

#### Create the permissions for the function
#### Get the function OCID
1. From the navigation menu, select **Functions** 
1. Click the Application Name
1. Click the Function Name
1. Copy the OCID ex. `ocid1.fnfunc.oc1.iad....`

#### Create the Dynamic Group
1. Copy the function OCID
1. From the navigation menu, select **Identity**, and then select **Dynamic Groups**.
1. Click `Create Dynamic Group1`
    1. Enter a Name
    1. Enter a Description
    1. Under `Matching Rules` 
        1. Select `Match all rules defined below`
        1. Under Rule 1 enter `resource.type = 'fnfunc'`
        1. Click `+Additional Rule`
        1. Under Rule 2 enter `resource.id = '<fnfunc_ocid>'`
    1. Click `Create`
    1. Remember your Dynamic Group Name for the next part

#### Create Policy
1. From the navigation menu, select **Identity**, and then select **Policies**.
1. Click `Create Policy`
    1. Enter a Name
    1. Enter a Description
    1. Select a Compartment
    1. Select `Show manual editor`
    1. Enter the below policy in the Policy Builder
    ```
    Allow dynamic-group <dynamic-group-name> to inspect tenancies in tenancy
    Allow dynamic-group <dynamic-group-name> to inspect compartments in tenancy
    Allow dynamic-group <dynamic-group-name> to inspect leaf-certificate-family in tenancy
    Allow dynamic-group <dynamic-group-name> to inspect certificate-authority-family in tenancy
    ```

#### Create and Event Rule to Send all Cloud Guard Problems to the Log

1. From the navigation menu, select **Events**, and then select **Rules**.
1. Select the `(root)` compartment
1. Click `Create Rule`


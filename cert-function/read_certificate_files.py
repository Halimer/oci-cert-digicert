import os
from pathlib import Path
 
class Certificate_Files:

    def __init__(self):
        pass


    ####################################################################################
    # Input: filepath
    # Actions: gets all pem files in the directory
    # returns: returns a list of all files in the directory
    ####################################################################################
    def __get_certs_in_directory(self,filepath):
        files_list = [f for f in os.listdir(filepath) if f.endswith('.pem')]
        return files_list

    def __covert_cert_to_str(self,file_name):
        cert_file = Path(file_name).read_text()
        str_cert = cert_file.encode("unicode_escape").decode("utf-8")
        return str_cert

    def get_certificates(self, directory):
        self.__directory = directory
        self.__cert_files = self.__get_certs_in_directory(self.__directory)
        for file in self.__cert_files:
            if 'cert' in file:
                self.__cert = self.__covert_cert_to_str(self.__directory + file)
            if 'privkey' in file:
                self.__privkey = self.__covert_cert_to_str(self.__directory + file)
            if 'chain' in file:
                self.__chain = self.__covert_cert_to_str(self.__directory + file)
        return {
            "cert_chain" : self.__chain,
            "certificate_pem" : self.__cert,
            "private_key_pem" : self.__privkey
        }
    

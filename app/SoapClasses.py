import datetime
import os
import random
import string
import uuid
from base64 import b64encode
from typing import Callable, List

import cryptography
import pandas as pd
import pytz
import rsa
import zeep
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives.serialization import pkcs12
from lxml import etree
from requests import Request, Session


class SoapID:

    """

    This class contains functions to generate ids and timestamps for the soap request. And a function to replace the keys in the xml text with the values in the replacements list.

    """

    def get_start_time(self) -> Callable[[], datetime.datetime]:
        """

        Returns a function that returns the current time in the correct format and timezone.

        """

        # create timestamps in the correct format and timezone, which seems to be utc
        current_date = datetime.datetime.now(tz=pytz.utc)

        return current_date

    def get_end_time(
        self, date: datetime.datetime, timediff: int = 5, unit="minuttes"
    ) -> datetime.datetime:
        """
        Get the end time for the soap request. The end time is five minuttes from the call itself.

        If days is used as unit the end time the function is used for specifying transaction start time/end time..

        """

        if unit == "minuttes":
            # the STS endpoint expects the end timepoint to be five minuttes from the call itself
            end_time = date + datetime.timedelta(minutes=timediff)

        elif unit == "days":
            end_time = date - datetime.timedelta(days=timediff)

        return end_time

    def format_time(self, date: datetime.datetime) -> datetime.datetime.strftime:
        """
        Format the time to the correct format for the soap request.

        """

        date_formated = date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return date_formated

    def id_generator(self, size: int = 32) -> str:
        """
        Generate a random string of letters and digits to use as id for the soap request.

        """

        chars = string.ascii_uppercase + string.digits

        return "".join(random.choice(chars) for _ in range(size))

    def replace_key_value(
        self, xml_text: str, keys: List[str], replacements: List[str]
    ) -> str:
        """
        Replace the keys in the xml text with the values in the replacements list.

        """

        for key, replacement in zip(keys, replacements, strict=False):
            if replacement == "NA":
                continue

            xml_text = xml_text.replace(key, replacement)

        return xml_text


class SoapCryptography:

    """

    This class contains functions to load the private key and certificate from the p12 file, extract the private key, sign the xml and get the digest.

    """

    def load_private_and_public_file(
        self, path_to_certificate_file_p12: str, password: str
    ) -> tuple[
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
        cryptography.x509.Certificate,
        list[cryptography.x509.Certificate],
    ]:
        with open(path_to_certificate_file_p12, "rb") as f:
            (
                private_key,
                certificate,
                additional_certificates,
            ) = pkcs12.load_key_and_certificates(f.read(), password.encode("utf8"))

        return private_key, certificate, additional_certificates

    def extract_private_key(
        self,
        private_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
        type_of_private_key="rsa",
    ) -> rsa.PrivateKey | str:
        """
        The data needs to be in the following format:

        -----BEGIN RSA PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGORvrUMdiYasA
        gKOEa+kXVFL480SHWZQIHu3E1k4M/v3ytu6Ky3+sQspGQ3H81Y309IAnhR6enSMy
        GvMEDBQwp/rhQ65ty/g6xsWiMJUBmEE6jTIKA6DIidgGL+xb5yZ4sgiHJnC5AYQh
        PplqET4mUDVrkH8BK0rJ1B5nB30Kwd2aKpKf7ecPQ7PT7T1aSyyGazjXCtKuF09y
        -----END RSA PRIVATE KEY-----
        """

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # The rsa library needs the private key in the following format:
        if type_of_private_key == "rsa":
            private_key = rsa.PrivateKey.load_pkcs1(pem_private_key)

            return private_key

        else:
            # The requests library needs the private key in the following format:
            return pem_private_key

    def sign_xml(self, xml_signature_element: str, private_key):
        """

        Sign the xml with the private key using the rsa library. Cryptography also has a sign function but it does not work with the STS endpoint.

        """

        signature = rsa.sign(
            xml_signature_element.encode("utf8"), private_key, "SHA-256"
        )

        signature = b64encode(signature).decode()

        return signature

    def get_digest(self, xml_string: str):
        """

        Get the digest of the xml string.

        """

        hasher = Hash(hashes.SHA256())

        hasher.update(xml_string.encode("utf8"))

        b64_decoded_digest = b64encode(hasher.finalize()).decode()

        return b64_decoded_digest

    def convert_pem_file_to_long_string(
        self, certificate: cryptography.x509.Certificate, remove_comments: bool = True
    ) -> str:
        """

        Convert the certificate from the p12 file to a long string. The soap file only needs the values not start, end or newlines.

        The requests library needs the certificate with the start and end values.

        """

        cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

        if remove_comments is True:
            cert_pem = (
                cert_pem.decode("utf8")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "")
            )

            return cert_pem

        else:
            return cert_pem


class SoapXML(SoapID, SoapCryptography):

    """

    This class contains functions to create the soap xml file, extract the elements that need to be canonicalized and create the search strings for the canonicalization.

    """

    def create_search_string_for_xpath(self, elements, ids_prefix, initialized_ids):
        """
        This function creates search strings to be used for canonicalization in the process of preparing the soap message.
        The canonicalized version needs to be done for each element and NOT for the entire xml file so we need to extract them separately.
        Only the digest ids and the signature value needs to be canonicalized.

        """

        search_strings = []

        for key, prefix, initialized_id in zip(
            elements.items(), ids_prefix, initialized_ids, strict=False
        ):
            # no id for signedinfo
            if key[0] == "SignedInfo" or key[0] == "Assertion":
                search_string = f".//{key[1][0]}{key[0]}"
                search_strings.append(search_string)

            # only use those values who need id i.e. digest values to calculate namespaces. The rest of the ids, i.e. timestamp and so on does not need a namespace since we do not need to canonicalize it.
            else:
                search_string = (
                    f'.//{key[1][0]}{key[0]}[@{key[1][1]}Id="{prefix}{initialized_id}"]'
                )
                search_strings.append(search_string)

        return search_strings

    def canonicalizer(self, xml_string, search_strings_for_tags, ns_prefixes: list):
        """

        Canonicalize the xml string. The canonicalization is done for each element separately.

        """

        tree = etree.XML(xml_string)
        c14_results = []
        for search_string, ns_prefix in zip(
            search_strings_for_tags, ns_prefixes, strict=False
        ):
            try:
                canonicalized_node = tree.findall(search_string)

                # if the node is not found. In order to keep the order of the list the same, as for the calculated ids, we append NA
                if len(canonicalized_node) == 0:
                    c14_results.append("NA")

                for result in canonicalized_node:
                    c14n_canonicalized = etree.tostring(
                        result,
                        method="c14n",
                        exclusive=True,
                        with_comments=False,
                        inclusive_ns_prefixes=ns_prefix,
                    )
                    c14_results.append(c14n_canonicalized.decode("utf8"))
            except Exception:
                c14_results.append("NA")
        return c14_results

    def set_digest_on_xml(self, xml_text, xml_string_canonical, ids_for_canonical):
        """

        Set the digest on the xml file. NA is used for those elements that are not found in the xml file to keep the order of the list the same as for the calculated ids.

        """

        # calculate digest
        digests = []

        for element in xml_string_canonical:
            if element == "NA":
                digests.append("NA")
                continue

            digest_temp = self.get_digest(element)
            digests.append(digest_temp)

        self.digests = digests

        # replace ids with digest
        xml_text = self.replace_key_value(xml_text, ids_for_canonical, digests)

        return xml_text

    def add_ids_to_xml(self):
        # Set time to current time and time + 5 minuttes and format to correct format
        self.start_time = self.get_start_time()
        self.end_time = self.get_end_time(self.start_time)
        self.start_time = self.format_time(self.start_time)
        self.end_time = self.format_time(self.end_time)

        # replace text in xml file with ids
        self.xml_text = self.replace_key_value(
            self.xml_text, self.ids_for_xml, self.ids_calculated
        )

    def add_digests_to_xml(self):
        """

        Add the digests to the xml file. The digests are calculated from the canonicalized xml string.

        """

        search_strings_for_canonicalizer = self.create_search_string_for_xpath(
            self.elements_to_use_for_canonicalization,
            self.ids_prefix,
            self.ids_calculated,
        )

        canonicalized_string = self.canonicalizer(
            self.xml_text, search_strings_for_canonicalizer, self.ns_prefixes
        )

        self.xml_text = self.set_digest_on_xml(
            self.xml_text, canonicalized_string, self.digest_signature
        )

        return self.xml_text

    def add_signature_to_xml(self):
        """

        Add the signature to the xml file. The signature is calculated from the canonicalized xml string.

        """

        search_strings_for_canonicalizer = self.create_search_string_for_xpath(
            self.elements_to_use_for_canonicalization_sig,
            self.ids_prefix_sig,
            self.ids_calculated_sig,
        )

        # get canonicalized signature after digest has been inserted
        canonicalized_signature = self.canonicalizer(
            self.xml_text, search_strings_for_canonicalizer, self.ns_prefixes_sig
        )

        # remove the first element which is the signedinfo element. Only relevant if there is more than one signature.
        if len(canonicalized_signature) > 1:
            canonicalized_signature = canonicalized_signature[1:]

        for index, canonicalized in enumerate(canonicalized_signature):
            # get signature from SignedInfo element after it has ben populated with digest values
            signature = self.sign_xml(canonicalized, private_key=self.private_key)
            # insert signature in xml file
            self.xml_text = self.replace_key_value(
                self.xml_text, [f"%%SIGVAL{index+1}%%"], [signature]
            )

    def create_body_for_xml_service(
        self,
        service: str,
        service_operation: str,
        method_for_service_operation,
        path_to_wsdl_file: str,
    ) -> str:
        """

        Create the body for the xml service. The body is created using zeep if the body does not exist. If the body exists it is loaded from the file.

        """

        # load file with body if it exists
        if os.path.exists(f"./files_with_body_templates/body_{service_operation}.xml"):
            with open(
                f"./files_with_body_templates/body_{service_operation}.xml",
                "r",
                encoding="utf8",
            ) as f:
                full_body = f.read()
            return full_body

        # use zeep to create the body if it doesnt exist. Requires downloading the documentation for the endpoint from https://digitaliseringskataloget.dk/ and pointing to the wsdl file using the "path_to_wsdl_file".
        else:
            # create client and add authority context
            client = zeep.Client(wsdl=f"{path_to_wsdl_file}")

            if service_operation=="PersonLookup":
                
                # create authority context using zeep
                soap_body = client.create_message(
                                    client.service,
                                    "PersonLookup",
                                    AuthorityContext={
                                        "MunicipalityCVR": os.environ["MUNICIPALITY_CVR"]},
                                    PNR="'%%MESSAGE_STRING%%'",
                                )
                
            elif service_operation=="callCPRPersonList":
                
                # create authority context using zeep
                soap_body = client.create_message(
                                    client.service,
                                    "callCPRPersonList",
                                    AuthorityContext={
                                        "MunicipalityCVR": os.environ["MUNICIPALITY_CVR"]},
                                    searchParameter="'%%MESSAGE_STRING%%'",
                                )           

            elif service_operation == "YdelseListeHentUDKKommuneService":
                transaktionsid = "%%TRANSAKTIONSID%%"
                transaktionstid = "%%TRANSAKTIONSTID%%"
                ns0_CPRNummerType = "%%MESSAGE_STRING%%"

                soap_body = client.create_message(
                    client.service,
                    "EffektueringHentUDKKommune",
                    HovedOplysninger={
                        "TransaktionsId": f"{transaktionsid}",
                        "TransaktionsTid": f"{transaktionstid}",
                    },
                    Kriterie={"PartCPRNummer": f"{ns0_CPRNummerType}"},
                    RettighedListe={
                        "BevillingDataAfgrGruppe": {
                            "MyndighedDataAfgrListe": {
                                "VirksomhedCVRNummer": os.environ["MUNICIPALITY_CVR"]
                            }
                        }
                    },
                    ResultatFilter={"ResultatStart": 0, "ResultatAntalMaks": 5000},
                    SorteringRetning="ASC",
                )

            if service_operation == "SF0770_A_IndkomstoplysningerLaes_IndkomstoplysningerLaes":

                person_id = "%%MESSAGE_STRING%%"
                start_date = "%%START_DATE%%"
                end_date = "%%END_DATE%%"

                transaktionsid = "%%TRANSAKTIONSID%%"
                transaktionstid = "%%TRANSAKTIONSTID%%"

                HovedOplysninger = {
                    
                        "TransaktionsId": f"{transaktionsid}",
                        "TransaktionsTid": f"{transaktionstid}",
                    
                }

                IndkomstOplysningPersonInddata = {
                    
                        "AbonnentAdgangStruktur": {
                            "AbonnentTypeKode": os.environ[
                                "ABONNENT_TYPE_KODE"
                            ],  # these three i.e. AbonnentTypeKode,AbonnementTypeKode and AdgangFormaalTypeKode are provided when signing the contract with SKAT
                            "AbonnementTypeKode": os.environ["ABONNEMENT_TYPE_KODE"],
                            "AdgangFormaalTypeKode": os.environ[
                                "ADGANG_FORMAAL_TYPE_KODE"
                            ],
                        },
                        "AbonnentStruktur": {
                            "AbonnentVirksomhedStruktur": {
                                "AbonnentVirksomhed": {
                                    "VirksomhedSENummerIdentifikator": os.environ[
                                        "SE_NUMMER_IDENTIFIKATOR"
                                    ]
                                }
                            }
                        },  # The SE number also comes from the agreement with SKAT
                        'IndkomstOplysningValg': {
                            'IndkomstPersonSamling': {
                                'PersonIndkomstSoegeStruktur': [
                                    {
                                        'PersonCivilRegistrationIdentifier': person_id,
                                        
                                        'SoegePeriodeLukketStruktur': {
                                            'DateInterval': {
                                                'StartDate': start_date,
                                                'EndDate': end_date  # Or DurationMeasure
                                            }
                                        }
                                    }
                                ]
                            }
                        }
                    }
                
                soap_body = client.create_message(
                    client.service,
                    "SF0770_A_IndkomstoplysningerLaes_IndkomstoplysningerLaes",
                    HovedOplysninger=HovedOplysninger,
                    IndkomstOplysningPersonInddata=IndkomstOplysningPersonInddata,
                )

                # extract content of body which is the third tagged element
                for index, child in enumerate(soap_body.iter()):
                    if index == 2:
                        content_of_body_tag = child.tag
                        content_of_body = soap_body.findall(f".//{content_of_body_tag}")

                # convert to string
                content_of_body_str = etree.tostring(content_of_body[0], encoding="unicode")

                # add correct start and end body with random id
                body_start = '<soap:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="_%%ID6%%">'
                body_end = "</soap:Body>"

                full_body = body_start + content_of_body_str + body_end

                with open(
                    f"./files_with_body_templates/body_{service_operation}.xml",
                    "w",
                    encoding="utf8",
                    ) as f:
                    f.write(full_body)


class SOAPHTTP:

    """

    Class for sending soap requests to endpoints.

    """

    def send_soap_sts(self):
        if self.certificate_endpoint in [
            "https://adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed",
            "https://adgangsstyring.stoettesystemerne.dk/runtime/services/kombittrust/14/certificatemixed",
        ]:
            headers = {
                "content-type": "application/soap+xml; charset=utf-8",
                "Accept": "*/*",
            }

        else:
            headers = {
                "content-type": "application/soap+xml; charset=utf-8",
                "Accept": "*/*",
                "SOAPAction": f'"{self.wsdl}"',
            }

        req = Request(
            "POST",
            self.certificate_endpoint,
            data=self.xml_text.encode("utf8"),
            headers=headers,
        )

        prepped = self.session.prepare_request(req)

        self.response = self.session.send(prepped)

        return self.response

    # extract variables from sts response
    def extract_variables_from_sts_response(self):
        tree = etree.XML(self.response.content.decode("utf8"))

        self.start_time = tree.findall(
            ".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Created"
        )[0].text
        self.end_time = tree.findall(
            ".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Expires"
        )[0].text
        self.saml_token = tree.findall(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
        )[4].text
        self.lifetime_created = tree.findall(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData"
        )[0].attrib["NotBefore"]
        self.lifetime_expires = tree.findall(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData"
        )[0].attrib["NotOnOrAfter"]
        self.saml_id = tree.findall(
            ".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
        )[0].attrib["ID"]
        self.cert_x509 = tree.findall(
            ".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
        )[0].text
        self.name_id = tree.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")[
            0
        ].text
        self.sigval_static = tree.findall(
            ".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue"
        )[1].text
        self.digest_static = tree.findall(
            ".//{http://www.w3.org/2000/09/xmldsig#}DigestValue"
        )[4].text


class SOAPSTS(SoapXML, SOAPHTTP):

    """
    Setting up variables to be used when caling the security token service (STS) endpoint for Serviceplatformen.
    """

    def __init__(
        self,
        test_or_prod: str = "test",
        service: str = "CPRQueryService",
        key_file_path: str = os.environ[
            "CERTIFICATE_NAME"
        ],  # certificate for kombit: "sp_devtest4_demoklient_sf0101_1.pfx",
        key_file_password: str = os.environ[
            "CERTIFICATE_PASSWORD"
        ],  # password for kombit: "1kKUWZ,91Zg1",
        cvr: str = os.environ["MUNICIPALITY_CVR"],
    ):  # "29189846"
        ###################################
        ## Constants initialized by input #
        ###################################

        self.test_or_prod = test_or_prod
        self.service = service
        self.key_file_path = "./auth_files/" + key_file_path
        self.key_file_password = key_file_password
        self.cvr = cvr

        #####################
        ## Choosing service #
        #####################

        # read file with all endpoints information.
        self.service_information_file = pd.read_excel(
            f"./background_on_endpoints/{self.test_or_prod}_services.xlsx",
            keep_default_na=False,
        )

        # subset to specific service
        self.service_information_file = self.service_information_file.query(
            "service=='{}'".format(self.service)
        )

        # This also changes the wsdl file which is used in the call to the service in the XML file
        # And the so-called "entity id" ID also differs for each service and is also sent in the XML file
        # The service operation is defined in the wsdl file for each integration. This also has several methods attached

        self.service_endpoint = self.service_information_file["service_endpoint"].iloc[
            0
        ]
        self.wsdl = self.service_information_file["wsdl"].iloc[0]
        self.serviceoperation = self.service_information_file["serviceoperation"].iloc[
            0
        ]
        self.method_for_serviceoperation = self.service_information_file[
            "method_for_serviceoperation"
        ].iloc[0]
        self.certificate_endpoint = self.service_information_file[
            "certificate_endpoint"
        ].iloc[0]
        self.saml_test_prod = self.service_information_file["saml_test_prod"].iloc[0]

        ######################################
        ## Constants variables automatically #
        ######################################

        # Set time to current time and time + 5 minuttes and format to correct format
        self.start_time = self.get_start_time()
        self.end_time = self.get_end_time(self.start_time)
        self.start_time = self.format_time(self.start_time)
        self.end_time = self.format_time(self.end_time)

        #########################
        ## Handle certificates ##
        #########################

        # Loads certificates into variables
        self.all_certificates = self.load_private_and_public_file(
            self.key_file_path, self.key_file_password
        )
        self.private_key = self.extract_private_key(self.all_certificates[0])
        self.cert_pem = self.convert_pem_file_to_long_string(self.all_certificates[1])

        # Writes public and private key in the correct formats to be used by the "requests" module as files when doing authentication
        with open("kombit_cert.cert", "wb") as f:
            f.write(
                self.convert_pem_file_to_long_string(
                    self.all_certificates[1], remove_comments=False
                )
            )
        with open("kombit_client.key", "wb") as f:
            f.write(
                self.extract_private_key(
                    self.all_certificates[0], type_of_private_key="str"
                )
            )

        ###################
        ## HTTP requests ##
        ###################

        # Set up session and endpoints

        self.session = Session()
        self.session.verify = "./auth_files/all_certificates.pem"  # potentially add more certificates to this file. This is simply the list of certificates from the requests package
        self.session.cert = ("kombit_cert.cert", "kombit_client.key")

        ####################
        ## XML processing ##
        ####################

        # open template file to be used to create digest values and insert unique ids and the current timestamp
        with open(
            "./files_with_sts_service_templates/template_sts.xml", "r", encoding="utf-8"
        ) as f:
            self.xml_text = f.read()

        # Placeholders for ids in xml files to be replaced
        self.ids_for_xml = [
            "%%ID1%%",
            "%%ID2%%",
            "%%ID3%%",
            "%%ID4%%",
            "%%ID5%%",
            "%%ID6%%",
            "%%ID7%%",
            "%%ID8%%",
            "%%ID9%%",
            "%%MESSAGE_ID%%",
            "%%CERT_PEM%%",
            "%%START_TIME%%",
            "%%END_TIME%%",
            "%%SERVICEENDPOINT%%",
            "%%CERTIFICATE_ENDPOINT%%",
            "%%CVR%%",
        ]

        # The variables the placeholders will be replaced with
        self.ids_calculated = [self.id_generator() for x in range(9)] + [
            str(uuid.uuid1()),
            self.cert_pem,
            self.start_time,
            self.end_time,
            self.service_endpoint,
            self.certificate_endpoint,
            self.cvr,
        ]

        # Ids for xpath expressions to extract elements from xml files using namespaces and "tags"
        self.elements_to_use_for_canonicalization = {
            "Action": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "MessageID": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "To": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "ReplyTo": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "Timestamp": [
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "Body": [
                "{http://www.w3.org/2003/05/soap-envelope}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "BinarySecurityToken": [
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
        }
        self.ids_prefix = (
            ["_"] * 4 + ["TS-"] + ["_"] + ["X509-"]
        )  # each id also has a prefix depending on the name which xpath needs in order to find it

        # Ids for digest values and namespace prefixes used when canonicalizing them
        self.digest_signature = [
            "%%DIGEST1%%",
            "%%DIGEST2%%",
            "%%DIGEST3%%",
            "%%DIGEST4%%",
            "%%DIGEST5%%",
            "%%DIGEST6%%",
            "%%DIGEST7%%",
        ]
        self.ns_prefixes = [[""]] * 7

        # Ids for signature values and namespace prefixes used when canonicalizing them
        self.elements_to_use_for_canonicalization_sig = {
            "SignedInfo": ["{http://www.w3.org/2000/09/xmldsig#}", " "]
        }
        self.ids_prefix_sig = ["-", "-"]
        self.ids_calculated_sig = ["-", "-"]
        self.ns_prefixes_sig = [[""]] * 1


class SOAPSERVICE(SOAPSTS):
    def __init__(self, soap_sts_instance, message: str):
        vars(self).update(vars(soap_sts_instance))
        self.message = message

        # start day is how many days in the past to extract data from eindkomst, and endday is set to day. Here we extract the last two years of data
        self.transaktions_tid = self.get_start_time()
        self.start_date = self.get_end_time(
            self.transaktions_tid, timediff=365 * 2, unit="days"
        )
        self.end_date = str(self.transaktions_tid.date())
        self.start_date = str(self.start_date.date())
        self.transaktions_id = str(uuid.uuid1())
        self.transaktions_tid = self.format_time(self.transaktions_tid)
        self.envelope_ns = self.service_information_file["envelope_ns"].iloc[
            0
        ]  # all namespaces except sf1492 have the same namespace but here it is different
        self.sbf = self.service_information_file["sbf"].iloc[0]
        self.sbf_digest = self.service_information_file["sbf_digest"].iloc[0]

        # change endpoint to service endpoint
        self.certificate_endpoint = self.service_information_file[
            "certificate_endpoint_service"
        ].iloc[0]

        #####################################
        ##  Prepare xml file for service   ##
        #####################################

        # create body and add to xml file
        with open(
            "./files_with_sts_service_templates/service_template.xml",
            "r",
            encoding="utf-8",
        ) as f:
            self.xml_text = f.read()

        body_for_xml = self.create_body_for_xml_service(
            self.service,
            self.serviceoperation,
            self.message,
            self.method_for_serviceoperation,
        )

        # add namespace for envelope, sbf information and body to xml file
        self.ids_calculated = [
            body_for_xml,
            self.envelope_ns,
            self.sbf,
            self.sbf_digest,
        ]
        self.ids_for_xml = ["%%BODY%%", "%%ENVELOPE_NS%%", "%%SBF%%", "%%SBF_DIGEST%%"]
        self.add_ids_to_xml()

        #########################################
        ## SET UP ids to calculate and replace ##
        #########################################

        self.ids_service_static = [
            "%%ID1%%",
            "%%ID2%%",
            "%%ID3%%",
            "%%ID4%%",
            "%%ID5%%",
            "%%ID6%%",
            "%%ID_TIMESTAMP%%",
            "%%ID_STR%%",
            "%%ID_SIG%%",
            "%%ID_KID%%",
            "%%MESSAGE_ID%%",
        ]

        self.ids_service = [
            "%%START_TIME%%",
            "%%END_TIME%%",  # start and end time for ORIGINAL sts response
            "%%SAMLID%%",  # SAMLUID from STS response
            "%%LIFETIME_CREATED%%",
            "%%ISSUE_INSTANT%%",
            "%%LIFETIME_EXPIRES%%",  # creation time and expires time from STS response for security token. CREATED and ISSUE instant are same
            "%%SAML_TEST_PROD%%",  # the endpoint for saml assertions i.e. test or prod endpoint
            "%%SAML_TOKEN%%",  # saml token from sts response
            "%%CERT_X509%%",
            "%%NAMEID%%",
            "%%CERT_PEM%%",
            "%%DIGEST_STATIC%%",
            "%%SIGVAL_STATIC%%",  # public key information. CERT_X509, and a single digest and a single signature is from STS response
            "%%CVR%%",
            "%%SERVICE_ENDPOINT%%",
            "%%WSDL%%",  # static variables
            "%%MESSAGE_STRING%%",  # what to send to the service
            "%%START_DATE%%",  # start date for data extraction
            "%%END_DATE%%",  # end date for data extraction
            "%%TRANSAKTIONSID%%",  # transaction id for service
            "%%TRANSAKTIONSTID%%",
        ]  # transaction time for service

        self.ids_for_xml = self.ids_service_static + self.ids_service

        self.ids_calculated = [self.id_generator() for x in range(10)] + [
            str(uuid.uuid1())
        ]
        self.ids_calculated = [
            *self.ids_calculated,
            self.start_time,
            self.end_time,
            self.saml_id,
            self.lifetime_created,
            self.lifetime_created,
            self.lifetime_expires,
            self.saml_test_prod,
            self.saml_token,
            self.cert_x509,
            self.name_id,
            self.cert_pem,
            self.digest_static,
            self.sigval_static,
            self.cvr,
            self.service_endpoint,
            self.wsdl,
            self.message,
            self.start_date,
            self.end_date,
            self.transaktions_id,
            self.transaktions_tid,
        ]

        ###############################################################
        ## SET UP IDS for calculation of digest and signature values ##
        ###############################################################

        self.elements_to_use_for_canonicalization = {
            "Framework": [
                "{urn:liberty:sb:2006-08}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "Action": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "MessageID": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "To": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "ReplyTo": [
                "{http://www.w3.org/2005/08/addressing}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "": [
                "*",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],  # no namespace to use for canonicalization since it changes across endpoints
            "Timestamp": [
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}",
            ],
            "Assertion": [
                "{urn:oasis:names:tc:SAML:2.0:assertion}",
                "{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}",
            ],
        }

        self.ids_prefix = ["_"] * 6 + ["TS-"] + ["_"] + ["STR-"]
        self.initialized_ids = [
            "%%ID1%%",
            "%%ID2%%",
            "%%ID3%%",
            "%%ID4%%",
            "%%ID5%%",
            "%%ID6%%",
            "%%ID_TIMESTAMP%%",
            "%%ID_STR%%",
        ]
        self.digest_signature = [
            "%%DIGEST1%%",
            "%%DIGEST2%%",
            "%%DIGEST3%%",
            "%%DIGEST4%%",
            "%%DIGEST5%%",
            "%%DIGEST6%%",
            "%%DIGEST_TIMESTAMP%%",
            "%%DIGEST_STR%%",
        ]
        self.ns_prefixes = [
            ["soap"],
            ["soap"],
            ["soap"],
            ["soap"],
            ["soap"],
            [""],
            ["wsse", "soap"],
            [""],
        ]
        self.ns_prefixes_sig = [["soap"]] * 2

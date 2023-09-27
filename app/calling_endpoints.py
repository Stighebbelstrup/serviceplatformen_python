import datetime
import logging
import os

import pandas as pd
import pytz
from SoapClasses import SOAPSERVICE, SOAPSTS

logger = logging.getLogger("serviceplatformen")


class calling_endpoints:
    def __init__(self) -> None:
        self.test_or_prod = os.environ.get("TEST_OR_PROD")

    def sts_service(self, service="QueryService"):
        # New soapservice instance for sts service
        new_sts = SOAPSTS(test_or_prod=self.test_or_prod, service=service)

        # add ids to xml_file
        new_sts.add_ids_to_xml()

        # calculate digests
        new_sts.add_digests_to_xml()

        # add signature
        new_sts.add_signature_to_xml()

        # send request to sts service
        new_sts.send_soap_sts()

        # extract information from sts
        new_sts.extract_variables_from_sts_response()

        return new_sts

    def service_call(self, sts_service, message=None):
        # add ids_to_service
        service_instance = SOAPSERVICE(sts_service, message=message)

        service_instance.add_ids_to_xml()

        #
        service_instance.add_digests_to_xml()

        # add signature
        service_instance.add_signature_to_xml()

        service_instance.send_soap_sts()

        return service_instance


class all_endpoints(calling_endpoints):
    def __init__(self):
        self.sts_placeholder = {
            "QueryService": None,
            "PersonBaseDataExtendedService": None,
            "EIndkomst": None,
            "YdelseListeHentUDKKommune": None,
            "DemoService": None,
        }

        calling_endpoints.__init__(self)

    def check_time(self, service):
        if self.sts_placeholder[service] is None:
            try:
                self.sts_placeholder[service] = self.sts_service(service=service)
            except Exception:
                logger.exception("Failed to call service sts: " + service)

        if pd.to_datetime(
            self.sts_placeholder[service].lifetime_expires
        ) > datetime.datetime.now(tz=pytz.utc):
            pass

        else:
            self.sts_placeholder[service] = self.sts_service(service=service)

    def call_endpoint(self, service, message):
        
        self.check_time(service)

        try:
            data = self.service_call(self.sts_placeholder[service], message=message)

            if data.response.status_code == 200:
                return data.response.content

            else:
                logger.exception(
                    "Error in status code for in service call for service: "
                    + service
                    + "status code: "
                    + str(data.response.status_code)
                )
                logger.debug(data.response.status_code)

                return data.response.status_code

        except Exception:
            logger.exception("Error in service call for service: " + service)

            return None

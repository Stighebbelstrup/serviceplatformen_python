# Table of Contents for Serviceplatformen API


- [Table of Contents for Serviceplatformen API](#table-of-contents-for-serviceplatformen-api)
- [Introduction](#introduction)
- [Creating a Python solution](#creating-a-python-solution)
  - [Templates](#templates)
  - [Digest values and signatures](#digest-values-and-signatures)
- [Services](#services)


# Introduction

This repository contains the API specification for the Danish public sector integration platform, Serviceplatformen using Python.

In general the solution works by sending a request to Serviceplatformens STS (Security Token Service) to get a token. This token is then used to access the different services provided by the public sector. In order for this to work the client needs to be set up with the correct certificates and public and private keys. See more here [Vejledning](https://digitaliseringskataloget.dk/l%C3%B8sninger/administrationsmodul). In short you need to be registered as a user with a specific certificate. The certificate is then used to authenticate the client.

The client also needs to be registered with the STS and the different services. For each service, e.g. *CPR replika opslag* documentation for the service can be found on [digitalseringskataloget](https://digitaliseringskataloget.dk/integration/sf1520). Sometimes, but not always, the endpoints for the service can be found online, and sometimes in the list of documentation for the service. The endpoints are also available in the WSDL files for the service. The WSDL files can be downloaded for each endpoint under [Download dokumentation](https://docs.kombit.dk/integration/sf1520/4.0/pakke). If a new service needs to be added, download all the documentation and point to the WSDL files in the code, and use Zeep to create a new body for the call. An example of setting this up can be found in the "Setting_up_demoservice_example.ipynb" notebook.

The registration is done by sending a request to the STS with the correct certificates and public and private keys. The request is signed with the private key and the signature is verified by the STS using the public key. The STS then returns a saml token, and some other relevant information, that needs to be sent to the service in order to get access to the data. The requests module is used to send the requests to the STS and the service and uses TLS and the certificates and keys to authenticate the client.


# Creating a Python solution

Currently only a Java solution and a .net solution is available. Documentation for these can be found on [github](https://github.com/Serviceplatformen). How to set them up and change them to fit different endpoints and types of authentication can be found here [Kom godt igang 1](https://digitaliseringskataloget.dk/files/integration-files/131120201133/Kom%20godt%20i%20gang%20-%20webservice.pdf) and here [Kom godt igang 2](https://digitaliseringskataloget.dk/files/integration-files/150920211601/Kom%20godt%20i%20gang%20-%20webservice%20OIOIDWS.pdf).

This is thus the first attempt at a Python solution, and probably needs a bit of work to be a general solution. Currently it is only tested with the services sf1520,sf0770,sf1492 but should work with other services as well if some additional work is done.

The current solution is not quite as flexible as the Java and .net solutions, but is based on lower level libraries and manual handling of the creation of the XML files being sent back and forth between the client and the server.

The solution is based on the following elements:
- Using templates for the creation of the XML files being sent to the server
- Manually calculating digests and signatures for the XML files
- Sending and receiving XML files using the requests library


## Templates

The templates for the STS service and the CPR/Eindkomst service is created using the Java client and then simply saving it as an xml file and inserting placeholders in this format ,%%PLACEHOLDER%%, for the information that needs to be inserted. The placeholders are then replaced with the correct information in the code. First a series of random IDs and the correct timestamps are inserted. In addition the files "prod_services.xlsx" and "test_services.xlsx", one for test, and one for production, are used to insert the correct endpoints, and some additional information, for the different services.

It is not always easy to find the relevant information about what should be inserted into the excel spreadsheet unfortunately. Sometimes the information can be found on the documentation for the service, sometimes in the WSDL file, and sometimes in the list of documentation for the service, and sometimes in the administrative module for the service. One thing that is certainly not obvious is the "soapAction" which, until the update of the Eindkomst service followed a relatively standardized pattern but is now completely different. It should be possible to find this in the wsdl file in the documentation under "soapAction". In the wsdl file for the new EIndkomst service this can e.g. be found in this part of the file:

```xml

<soap:operation xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
                soapAction="http://www.kombit.dk/2017/01/01/SKATForwardEIndkomstServiceService_4#SF0770_A_IndkomstoplysningerLaes_IndkomstoplysningerLaes"/>
<wsdl:input name="IndkomstOplysningPersonHent">
```

The "soapAction" is then the string after "soapAction=" i.e. "http://www.kombit.dk/2017/01/01/SKATForwardEIndkomstServiceService_4#SF0770_A_IndkomstoplysningerLaes_IndkomstoplysningerLaes" . The "soapAction" is then inserted into the excel spreadsheet under "wsdl".

The template for the service itself also requires some additional information. This is the information that is used to create the body of the XML file. This information is inserted into the template in the code using the %%BODY%% placeholder. The body contains information about the specific data that should be extracted, and sometimes some additional identifying information about who is making the request. This needs to be tailormade for each service and for each type of data. The Zeep library is used to create the body, and then the body is converted to a string and inserted into the template. Instead of creating the body using Zeep, it is also possible to create the body using the templates. This is done by creating a new template for the body and then inserting the placeholders for the information that needs to be inserted. The placeholders are then replaced with the correct information in the code. This is much faster than creating them from scratch each time and also requires all the background information needed to read and parse the WSDL file each time.


## Digest values and signatures


After inserting ids and timestamps into the XML file, the digest value is calculated and inserted into the XML file. This is based on the different ids and timestamps that are inserted into the XML file. The digest value is then signed and the signature is inserted into the XML file. When calling the service, i.e. after calling the STS, some additional information, such as a "fake" digest value and a "fake" signature, is extracted from the STS response and inserted into the XML file when making the request.

# Services

Currently the following services are supported:
- sf1520 (CPR)
- sf0770 (Eindkomst)
- sf1492 (Ydelsesdata)

In order to call the service we first import the SOAPSTS and the SOAPSERVICE classes from the SoapClasses module. An example of how to set this up is shown in the *calling_endpoints.py* file; this file is then used in the "app.py" to create an API to call. The SOAPSTS class is used to call the STS service and the SOAPSERVICE class is used to call the service itself. The SOAPSERVICE class is initialized with the endpoint for the service, the endpoint for the STS service, the path to the certificate and the path to the private key. The SOAPSERVICE class also contains a method for calling the service, and a method for calling the STS service. The STS service needs to know, in advance which service to call so when creating this class the "service" argument needs to be set to the correct service. The service itself is called by calling the "service" method. This method takes the following arguments:
- *QueryService* i.e. sf1520's query service
- *PersonBaseDataExtendedService* i.e. sf1520's PersonBaseDataExtendedService
- *EIndkomst* i.e. sf0770's EIndkomst
- *YdelseListeHentUDKKommune* i.e. sf1492's YdelseListeHentUDKKommune

In addition to choosing the correct service the "message" also needs to be created. Currently this is always a CPR-number except for the query service for sf1520, where it is a query correctly formated in the so-called solr format. It is also possible to specify a new path to the certificate but currently is set to the default value for the current certificate. An example call for the PersonBaseDataExtendedService and the QueryService could look like this:

```bash

#call the DemoService
curl http:/localhost:5000/serviceplatformen/DemoService?cpr=0307699999

#call the PersonBaseDataExtendedService
curl http:/localhost:5000/serviceplatformen/PersonBaseDataExtendedService?cpr=0307699999

#call the QueryService using the solr format with the query parameter 'q=(standardadresse:Akseltorv 1) AND (postnummer:6000)' that then should be url-encoded
curl http:/localhost:5000/serviceplatformen/QueryService?query=q%3D%28standardadresse%3AAkseltorv%201%29%20AND%20%28postnummer%3A6000%29

#call the EIndkomst service
curl http:/localhost:5000/serviceplatformen/EIndkomst?cpr=0307699999

#call the YdelseListeHentUDKKommune service
curl http:/localhost:5000/serviceplatformen/YdelseListeHentUDKKommune?cpr=0307699999

```

It should be possible to build the service and run it locally by using the Dockerfile and building it. E.g. `docker build -t serviceplatformen .` and then running it with `docker run -p 5000:5000 serviceplatformen`. 

When setting the services up the following environmental variables need to be set:
- *MUNICIPALITY_CVR* the cvr number of the municipality
- *TEST_OR_PROD* whether the test or production service should be used
- *CERTIFICATE_NAME* the name of the certificate
- *CERTIFICATE_PASSWORD* the password for the certificate


The following variables need to be set for the Eindkomst service:
- *AbonnentTypeKode* endpoint for the test service
- *AbonnementTypeKode* endpoint for the production service
- *AdgangFormaalTypeKode* endpoint for the test service
- *SEnummerIdentifikator* endpoint for the production service


The example body files, in the ./files_with_body_templates folder, are set-up to work with the default Kombit client used in the java client using the municipality cvr number here. Do NOT format the files in any way, i.e. do not add any newlines or spaces. The files are formatted in a specific way and will not work if the formatting is changed. The files are also set up to work with the default values for the different variables.

There are no default values for the Eindkomst service so here values of "9999" are inserted for the variables mentioned above.

For the YdelseListeHentUDKKommune service remember to subset the data to your needs and according to the purpose of the agreement with UDK according to "Lov om Udbetaling Danmark i §8 stk1 og §8 stk2".


# License

This code and repository are open source and available under the most permissive open source license. You are free to use, modify, and distribute the code as you see fit. However, please note that this comes without any warranty, and you use it at your own risk.

The work has been done as part of work at the Data Science team at the Municipality of Copenhagen but is not an official product of the Municipality of Copenhagen.

For licensing details, please refer to the [LICENSE](LICENSE) file.
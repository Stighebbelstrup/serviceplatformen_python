import logging
import sys

from calling_endpoints import all_endpoints
from flask import Flask, request
from loggingjson import setup_logger

setup_logger()
logger = logging.getLogger("serviceplatformen")


# initialize flask app
app = Flask(__name__)

# initialize sts services
sts_services_all = all_endpoints()


# create all endpoints. The endpoints are named using their service name
@app.route("/<service_endpoint>")
def service_call(service_endpoint):
    if service_endpoint == "QueryService":
        text = request.args.get("query")

    else:
        text = request.args.get("cpr")

    result = sts_services_all.call_endpoint(service_endpoint, text)

    return result


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")

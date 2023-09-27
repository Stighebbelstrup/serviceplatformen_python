FROM ubuntu:22.04

######################
###   Base Setup   ###
######################

# Installing linux dependency
RUN apt-get update && apt-get -y install gcc curl git pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl pip

######################
### Language Setup ###
######################
# Setting up danish language
RUN apt-get update && apt-get install -y locales
RUN localedef -i da_DK -c -f UTF-8 -A /usr/share/locale/locale.alias da_DK.UTF-8
ENV LANG da_DK.utf8

# Setting up danish timezone
ENV DEBIAN_FRONTEND="noninteractive" TZ="Europe/Copenhagen"
RUN apt-get -y install tzdata

##################
### User Setup ###
##################

# Setting up webapp user
RUN adduser --uid 8877 appuser
USER appuser
WORKDIR /home/appuser/app/

# Copying requirements to image
COPY --chown=appuser:appuser /app .
COPY --chown=appuser:appuser requirements.txt requirements.txt

# Adding local bin to path
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Installing python dependencies and setting up environment variables.
ENV MUNICIPALITY_CVR=29189846
ENV TEST_OR_PROD=test
ENV CERTIFICATE_NAME=sp_devtest4_demoklient_sf0101_1.pfx
ENV CERTIFICATE_PASSWORD=1kKUWZ,91Zg1

RUN pip install --no-cache-dir -r requirements.txt


####################
### Starting App ###
####################

EXPOSE 5000
# Starting App at Container start
CMD ["uwsgi", "--ini", "wsgi.ini"]

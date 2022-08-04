import os

# ENV for PRIVATE_KEY
ENV_PRIVATE_KEY = "SATELLITE_KEY"

# ENV for certificate chain
ENV_CERTIFICATES = "SATELLITE_CERTS"

# Obtain private key from yaml or ENV
def get_private_key(config):
    return os.environ.get(ENV_PRIVATE_KEY, config['key'])

# Obtain certificate chains from yaml or ENV
def get_certificates(config):
    return os.environ.get(ENV_CERTIFICATES, config['crt'])

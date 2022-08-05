import jwt
import os
import time
import uuid

# /token endpoint
TOKEN_ENDPOINT = "/token"

# Create iSHARE JWT token
def create_request_token(client_id, satellite_id, key, crt):

    def getCAChain(cert):

        sp = cert.split('-----BEGIN CERTIFICATE-----\n')
        sp = sp[1:]

        ca_chain = []
        for ca in sp:
            ca_sp = ca.split('\n-----END CERTIFICATE-----')
            ca_chain.append(ca_sp[0])
            
        return ca_chain

    iat = int(str(time.time()).split('.')[0])
    exp = iat + 30
    
    token = {
        "jti": str(uuid.uuid4()),
        "iss": client_id,
        "sub": client_id,
        "aud": [
            satellite_id
        ],
        "iat": iat,
        "nbf": iat,
        "exp": exp
    }

    return jwt.encode(token, key, algorithm="RS256", headers={
        'x5c': getCAChain(crt)
    })

# Decode iSHARE JWT
def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})

# Encode token
def encode_token(token, key, x5c=None):
    headers = {}
    if x5c is not None:
        headers['x5c'] = x5c

    return jwt.encode(token, key, algorithm="RS256", headers=headers)

# Get access token
def get_access_token(client, client_id, satellite_id, key, crt):
    # Auth params
    auth_params = {
        'grant_type': 'client_credentials',
        'scope': 'iSHARE',
        'client_id': client_id,
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': None
    }
    
    # Get request token
    token = create_request_token(client_id=client_id, satellite_id=satellite_id, key=key, crt=crt)
    auth_params['client_assertion'] = token

    # Invoke request
    response = client.post(TOKEN_ENDPOINT, data=auth_params)

    return response.json['access_token']

# Minimal example setup and request

In this description we'll make minimal changes to the sample configuration of the
satellite and make a request to the `parties` endpoint.

## Preparation

In this section we'll configure the satellite using:

- self signed certificates
- one CA certificate in trusted list
- no intermediate certificates

### Generate certificates

We're only using self signed certificate in this example.  So we need to generate our own
CA certificate:

```sh
openssl req \
  -x509 -newkey rsa:4096 -sha256 -days 365 -noenc \
  -keyout ca.key.pem -out ca.cert.pem \
  -subj "/CN=CA"
```

Generate a certificate for the satellite (signed by our CA certificate):

```sh
openssl req \
  -x509 -newkey rsa:4096 -sha256 -days 365 -noenc \
  -keyout sat.key.pem -out sat.cert.pem \
  -subj "/CN=Satellite/serialNumber=SATELLITE.EORI" \
  -CA ca.cert.pem -CAkey ca.key.pem
```

Generate a certificate for a party in the configuration file (also signed by our CA
certificate):

```sh
openssl req \
  -x509 -newkey rsa:4096 -sha256 -days 365 -noenc \
  -keyout party.key.pem -out party.cert.pem \
  -subj "/CN=Satellite/serialNumber=EU.EORI.NLPACKETDEL" \
  -CA ca.cert.pem -CAkey ca.key.pem
```

We'll be using this party's certificate to access the satellite.

### Configure satellite

Make the following changes in `config/satellite.yml`:

- Replace `<SATELLITE_EORI>` at `id` with `SATELLITE.EORI` (because we can't have `<`, `>`
  or `_` in a X509 subject serialNumber value)
  
- Set the content of `sat.key.pem` at `key`

- Set the content of both `sat.cert.pem` and `ca.cert.pem` at `crt` (note we
  don't have an intermediate certificate in this example)

- Set `trusted_list` property `crt` of the `iShareTestCA` entry to the content of
  `ca.cert.pem`, and drop the `FIWARETEST-CA` entry from `trusted_list`

## Get token from endpoint

First we create a bearer to be used as client assertion for the token endpoint.

```python
import jwt, re

def clean_cert(s):
    return re.sub('-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n', '', s)

party_key = open('party.key.pem', 'r').read(-1)
party_cert = clean_cert(open('party.cert.pem', 'r').read(-1))
ca_cert = clean_cert(open('ca.cert.pem', 'r').read(-1))

print(jwt.encode({
    'iat': 1500000000,
    'exp': 2000000000,
    'iss': 'EU.EORI.NLPACKETDEL', # from parties in config/satellite.yml
    'aud': 'SATELLITE.EORI' # from id in config/satellite.yml
}, party_key, algorithm='RS256', headers={
    'x5c': [party_cert, ca_cert]
}))
```

Now call the `/token` endpoint with that token (in environment variable `TOKEN`):

```sh
curl -s \
  -d 'client_id=EU.EORI.NLPACKETDEL' \
  -d grant_type=client_credentials \
  -d scope=iSHARE \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=$TOKEN \
  http://localhost:8080/token
```

This returns something like the following:

```json
{
  "access_token": "eyabc.eyxyz.blabla",
  "expires_in": 3600,
  "scope": "iSHARE",
  "token_type": "Bearer"
}
```

Take the `access_token` (note: it's a lot longer that the example above) and use it to
call on other endpoints.

## Get parties from endpoint

With the token from the previous step (in environment variable `ACCESS_TOKEN`, we can now
call the parties endpoint.  This endpoint requires an argument to let's query it with the
name of another party in the sample configuration file:

```sh
curl -s
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/parties?name=HappyPets
```

This returns the parties wrapped up in a JWT token:

```json
{
  "parties_token": "eyabc.eyxyz.blabla"
}
```

Decode the token to see what's in it with:

```python
import jwt, sys, json

print(
    json.dumps(
        jwt.decode("eyabc.eyxyz.blabla", options={"verify_signature": False})
    )
)
```

This returns something like:

```json
{
  "parties_info": {
    "count": 1,
    "data": [
      {
        "party_id": "EU.EORI.NLHAPPYPETS",
        "party_name": "HappyPets",
        "adherence": {
          "end_date": "2051-09-27T00:00:00Z",
          "start_date": "2021-09-27T00:00:00Z",
          "status": "NotActive"
        }
      }
    ]
  },
  "iss": "SATELLITE.EORI",
  "sub": "SATELLITE.EORI",
  "aud": "EU.EORI.NLPACKETDEL",
  "iat": 1681303064,
  "exp": 1681303094,
  "jti": "36045465-1560-42e2-9603-b51a78e13bd8"
}
```

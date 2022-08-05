import pytest
from api import app
from tests.pytest.util.config_handler import load_config
from tests.pytest.util.token_handler import decode_token, get_access_token
import time

# Get satellite config
satellite_config = load_config("tests/config/satellite.yml", app)
app.config['satellite'] = satellite_config

# Get client config
client_config = load_config("tests/config/client_fiware.yml", app)

# /trusted_list endpoint
TRUSTED_LIST_ENDPOINT = "/trusted_list"

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

# Successful trusted_list
@pytest.mark.ok
@pytest.mark.it('Successfully request /trusted_list')
def test_trusted_list_ok(client):
    # Get access token
    access_token = get_access_token(client=client, client_id=client_config['id'], satellite_id=satellite_config['id'], key=client_config['key'], crt=client_config['crt'])

    # Set header
    headers = {
        'Authorization': 'Bearer ' + access_token
    }

    # Invoke request
    response = client.get(TRUSTED_LIST_ENDPOINT, headers=headers)
    
    # Status code
    assert response.status_code == 200

    # Trusted list token exists
    assert 'trusted_list_token' in response.json

    # Decode token
    trusted_list_token = decode_token(response.json['trusted_list_token'])
    
    # versions token parameters
    assert trusted_list_token['aud'] == client_config['id']
    assert trusted_list_token['iss'] == satellite_config['id']
    assert trusted_list_token['sub'] == satellite_config['id']

    # Valid expiration claim
    now = int(str(time.time()).split('.')[0])
    assert trusted_list_token['iat'] <= now
    assert trusted_list_token['exp'] > now

    # Verify trusted list
    assert len(trusted_list_token['trusted_list']) == 2
    assert trusted_list_token['trusted_list'][0]['certificate_fingerprint'] == "A78FDF7BA13BBD95C6236972DD003FAE07F4E447B791B6EF6737AD22F0B61862"
    assert trusted_list_token['trusted_list'][1]['certificate_fingerprint'] == "8ECB9BD8E0FE12D7368ACDE12905E823812C34A71F97439D9E42383477C94E2B"


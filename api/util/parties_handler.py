import os, json, jwt, re, http, urllib, time
from flask import abort
from api.util.token_handler import get_subject_components_full, get_certificates_info

# Maximum of parties per page
MAX_PER_PAGE = int(os.environ.get('SATELLITE_MAX_PARTIES_PER_PAGE', 10))

# Request must contain at leat one of these parameters
MINIMUM_PARAMETERS = ['name', 'eori', 'certified_only', 'active_only', 'certificate_subject_name']

def to_bool(value):
    if value is None:
        return None
    
    if value.lower() in ['True', 'true']:
        return True
    elif value.lower() in ['False', 'false']:
        return False

    return None

# Check for parameter requirements (returns None if params ok)
def check_invalid_parameters(request):

    # Check for minimum parameters
    ok = False
    for p in MINIMUM_PARAMETERS:
        opt_param = request.args.get(p)
        if opt_param:
            ok = True
            break
    if not ok:
        return "At least one parameter needs to be specified"

    # Check certificate_subject_name vs eori
    opt_param = request.args.get('certificate_subject_name')
    if opt_param:
        eori_param = request.args.get('eori')
        if not eori_param:
            return "The certificate_subject_name should be used in combination with the eori parameter"
        if eori_param == "*":
            return "The eori parameter should not contain '*' when certificate_subject_name parameter is used"

    # Check booleans
    r_certified = request.args.get('certified_only')
    if (r_certified is not None) and (r_certified != 'null'):
        if to_bool(r_certified) is None:
            return "Invalid value {} for parameter certified_only".format(r_certified)
    r_active = request.args.get('active_only')
    if (r_active is not None) and (r_active != "null"):
        if to_bool(r_active) is None:
            return "Invalid value {} for parameter active_only".format(r_active)

    # Check page parameter > 0
    r_page = request.args.get('page')
    if (r_page is not None):
        try:
            page = r_page
            if not isinstance(r_page, int):
                page = int(r_page)
            if page < 1:
                return "Parameter 'page' must be > 0"
        except Exception as ex:
            return 'Parameter page cannot be converted to int: {}'.format(ex)
        
    return None

# Check certificate_subject_name of party certificate
def check_certificate_subject_name(certificate_subject_name, request_eori, party, app):

    app.logger.debug("Compare requested certificate subject name for {}".format(party['id']))
    
    # Get subject_name components from party certificate
    crt = party['crt']
    crt_subject_components : dict = get_subject_components_full(crt)

    # Split request subject_name components
    r_subject_components = []
    r_sub_array = certificate_subject_name.split(',')
    for s in r_sub_array:
        comp = s.strip().split('=')
        r_subject_components.append(comp)

    app.logger.debug("==> Requested: {}".format(r_subject_components))
    app.logger.debug("==> Certificate: {}".format(crt_subject_components))
      
    # check serial number
    if 'serialNumber' in crt_subject_components:
        if request_eori != crt_subject_components['serialNumber']:
            app.logger.debug("Wrong serialNumber in certificate subject name")
            return False  

    # Iterate over requested subject name attributes
    for r in r_subject_components:
        if r[0].strip() in crt_subject_components:
            if crt_subject_components[r[0].strip()] != r[1].strip():
                app.logger.debug("Certificate subject name does not match")
                return False

    app.logger.debug("Subject certificate name matched")
    return True

# Paginate parties_info
def paginate_parties(parties_info, page):

    # All parties
    full_data = parties_info['data']

    # Directly return empty list
    if len(full_data) < 1:
        return parties_info

    # Get subset
    page = int(page)
    start = (page-1)*MAX_PER_PAGE
    end = page * MAX_PER_PAGE
    data = parties_info['data'][int(start):int(end)]

    # Replace and return
    parties_info['data'] = data
    return parties_info

# Build parties_info
def get_parties_info(request, config, app):

    # Return object
    parties_info = {
        'count': 0,
        'data': []
    }

    registrar_id = request.args.get('registrar_id')
    if registrar_id and registrar_id != config['id']:
        return get_associate_parties_info(request, config, app)

    # Iterate over parties
    if 'parties' not in config:
        app.logger.error('No parties specified in config')
        return parties_info
    for p in config['parties']:

        app.logger.debug("Compare request to participant: {}".format(p['id']))

        # Check for name
        r_name = request.args.get('name')
        if (r_name is not None) and (r_name != "*") and (r_name != p['name']):
            continue

        # Check for eori
        r_eori = request.args.get('eori')
        if (r_eori is not None) and (r_eori != "*") and (r_eori != p['id']):
            continue

        # Check for certifications
        r_certified = to_bool(request.args.get('certified_only'))
        if r_certified is not None:
            app.logger.debug("Check for requested participant certification")
            if (r_certified == True) and ('certifications' not in p):
                continue
            elif (r_certified == False) and ('certifications' in p):
                continue
                
        # Check for status
        r_active = to_bool(request.args.get('active_only'))
        if r_active is not None:
            app.logger.debug("Check for requested participant status")
            if (r_active == True) and (p['status'] != "Active"):
                continue
            elif (r_active == False) and (p['status'] == "Active"):
                continue

        # Check certificate_subject_name
        r_certificate_subject_name = request.args.get('certificate_subject_name')
        if r_certificate_subject_name is not None:
            if not check_certificate_subject_name(r_certificate_subject_name, r_eori, p, app):
                continue

        # Append data
        app.logger.debug("Participant '{}' passed, adding to result list".format(p['id']))
        party = {
            'party_id': p['id'],
            'party_name': p['name'],
            'registrar_id': config['id'],
            "adherence": {
                "end_date": p['end_date'],
                "start_date": p['start_date'],
                "status": p['status']
            }
        }
        if 'certifications' in p:
            party['certifications'] = p['certifications']
        if 'capability_url' in p:
            party['capability_url'] = p['capability_url']
        else:
            party['capability_url'] = ""
        if 'crt' in p:
            party['certificates'] = get_certificates_info(p['crt'], app)
        if 'additional_info' in p:
            party['additional_info'] = p['additional_info']
        if 'agreements' in p:
            party['agreements'] = p['agreements']
        if 'roles' in p:
            party['roles'] = p['roles']
        if 'authregistery' in p:
            party['authregistery'] = p['authregistery']
        else:
            party['authregistery'] = []

        parties_info['count'] += 1
        parties_info['data'].append(party)
        
    # Return data
    return parties_info

def trim_cert(cert):
    return re.sub('-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n', '', cert)

def get_associate_parties_info(request, config, app):
    associate_path = request.args.get('registrar_id').split(',')
    if associate_path[0] != config['id']:
        app.logger.error(f"Associate does not start with this instance: '{associate_path[0]}'")
        abort(400)

    associate_id = associate_path[1]
    app.logger.debug(f"Will query associate '{associate_id}'")

    associate = None
    try:
        associate = config['associates'][associate_id]
    except KeyError:
        app.logger.error(f"Associate not configured: '{associate_id}'")
        abort(400)

    associate = config['associates'][associate_id]
    url = urllib.parse.urlparse(associate['url'])
    hostname = url.netloc
    if url.scheme == 'http':
        client = http.client.HTTPConnection(hostname)
    else:
        client = http.client.HTTPSConnection(hostname)

    ####################
    # Acquire access token

    iat = int(time.time())
    exp = iat + 3600
    client_assertion = jwt.encode({
        'iat': iat,
        'exp': exp,
        'iss': config['id'],
        'aud': associate_id
    }, config['key'], algorithm='RS256', headers={
        'x5c':
        [trim_cert(cert) for cert in config['crt'].split('-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----')] +
        [trim_cert(cert['crt']) for cert in config['trusted_list']]
    })

    params = {
        'client_id': config['id'],
        'grant_type': 'client_credentials',
        'scope': 'iSHARE',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': client_assertion
    }
    headers = {
        'Content-type': 'application/x-www-form-urlencoded'
    }

    app.logger.debug(f"Calling /connect/token endpoint at '{hostname}'")
    client.request('POST', '/connect/token', urllib.parse.urlencode(params), headers)
    res = client.getresponse()

    if res.status != 200:
        app.logger.error(f"Got bad response from satellite: '{res.read()}'")
        abort(400, description=f'can not connect to satellite: {associate_id}')

    access_token = json.load(res)['access_token']

    ####################
    # Get parties

    params = request.args.to_dict()
    associate_path = associate_path[1::] # pop current satellite of the path
    params['registrar_id'] = str.join(',', associate_path)
    params = urllib.parse.urlencode(params)

    app.logger.debug(f"Calling /parties endpoint at '{hostname}'")
    client.request('GET', f'/parties?{params}', None, {'Authorization': f'Bearer {access_token}'})
    res = client.getresponse()

    if res.status != 200:
        abort(400, f'querying parties failed: {res.read()}')

    parties_token = json.load(res)['parties_token']
    return jwt.decode(parties_token, options={"verify_signature": False})['parties_info']

# webauthn.py
import os
import json
from flask import session, request
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
)

# In-memory credential storage (replace with database in production)
credentials_db = {}

def get_rp_id():
    return request.host.split(':')[0]

def get_origin():
    return request.url_root.rstrip('/')

def begin_registration(username):
    user_id = os.urandom(32)
    challenge = os.urandom(32)

    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name="Task Manager",
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        timeout=60000,
        challenge=challenge,
        pub_key_cred_params=[{"type": "public-key", "alg": -7}],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    session['webauthn_challenge'] = challenge
    session['webauthn_user_id'] = user_id

    return json.loads(options.json())

def complete_registration(username, credential_json):
    if username in credentials_db:
        raise Exception("User already registered")

    credential = RegistrationCredential.parse_raw(json.dumps(credential_json))
    challenge = session.pop('webauthn_challenge', None)
    if not challenge:
        raise Exception("No challenge found")

    verification = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=get_rp_id(),
        expected_origin=get_origin(),
        require_user_verification=True,
    )

    credentials_db[username] = {
        "credential_id": verification.credential_id,
        "public_key": verification.credential_public_key,
        "sign_count": verification.sign_count,
    }

    return {"verified": True}

def begin_authentication(username):
    if username not in credentials_db:
        raise Exception("User not registered")

    challenge = os.urandom(32)
    session['webauthn_challenge'] = challenge

    allow_credentials = [
        PublicKeyCredentialDescriptor(type="public-key", id=credentials_db[username]["credential_id"])
    ]

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        challenge=challenge,
        timeout=60000,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    return json.loads(options.json())

def complete_authentication(username, credential_json):
    if username not in credentials_db:
        raise Exception("User not registered")

    credential = AuthenticationCredential.parse_raw(json.dumps(credential_json))
    challenge = session.pop('webauthn_challenge', None)
    if not challenge:
        raise Exception("No challenge found")

    stored = credentials_db[username]

    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=get_rp_id(),
        expected_origin=get_origin(),
        credential_public_key=stored["public_key"],
        credential_current_sign_count=stored["sign_count"],
        require_user_verification=True,
    )

    stored["sign_count"] = verification.new_sign_count

    return {"verified": True}

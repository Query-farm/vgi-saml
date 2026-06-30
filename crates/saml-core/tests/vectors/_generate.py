#!/usr/bin/env python3
"""Generate golden SAML fixtures (signed + tampered + XSW) as a crypto oracle.

Uses signxml (exclusive C14N, enveloped RSA-SHA256 / ECDSA-P256) to produce
*correctly* signed assertions, then derives tampered and signature-wrapping
variants. The Rust worker's C14N/verify must agree with these.
"""
import base64
import hashlib
import os
import sys
from copy import deepcopy

from lxml import etree
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

from signxml import XMLSigner, XMLVerifier, methods

OUT = sys.argv[1] if len(sys.argv) > 1 else "vectors"
os.makedirs(OUT, exist_ok=True)

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
    "xs": "http://www.w3.org/2001/XMLSchema",
}


def make_cert(key, cn):
    pub = key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert


def assertion_xml(aid="_a1", subject="alice@example.com"):
    return f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{aid}" Version="2.0" IssueInstant="2026-06-01T12:00:00Z">
  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress" SPNameQualifier="https://sp.example.com">{subject}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="2026-06-01T12:10:00Z" Recipient="https://sp.example.com/acs" InResponseTo="_req1"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2026-06-01T11:55:00Z" NotOnOrAfter="2026-06-01T12:10:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="2026-06-01T12:00:00Z" SessionIndex="_sess123" SessionNotOnOrAfter="2026-06-01T20:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="email">
      <saml:AttributeValue xsi:type="xs:string">{subject}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="role">
      <saml:AttributeValue>admin</saml:AttributeValue>
      <saml:AttributeValue>user</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"""


def response_wrap(assertion_elem, rid="_r1"):
    resp = etree.Element("{urn:oasis:names:tc:SAML:2.0:protocol}Response", nsmap={"samlp": NS["samlp"], "saml": NS["saml"]})
    resp.set("ID", rid)
    resp.set("Version", "2.0")
    resp.set("IssueInstant", "2026-06-01T12:00:01Z")
    resp.set("Destination", "https://sp.example.com/acs")
    resp.set("InResponseTo", "_req1")
    issuer = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer.text = "https://idp.example.com/saml"
    status = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
    sc = etree.SubElement(status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    sc.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
    resp.append(assertion_elem)
    return resp


def write(name, data):
    if isinstance(data, str):
        data = data.encode()
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)
    print(f"wrote {name} ({len(data)} bytes)")


# --- keys/certs: RSA + EC ---
rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_cert = make_cert(rsa_key, "idp.example.com RSA")
ec_key = ec.generate_private_key(ec.SECP256R1())
ec_cert = make_cert(ec_key, "idp.example.com EC")

for tag, key, cert in [("rsa", rsa_key, rsa_cert), ("ec", ec_key, ec_cert)]:
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    write(f"cert_{tag}.pem", cert_pem)
    write(f"cert_{tag}.der", cert_der)
    write(f"cert_{tag}.sha256", hashlib.sha256(cert_der).hexdigest())

    sig_alg = "rsa-sha256" if tag == "rsa" else "ecdsa-sha256"

    # Sign the ASSERTION (enveloped, exclusive c14n).
    a = etree.fromstring(assertion_xml().encode())
    signer = XMLSigner(method=methods.enveloped, signature_algorithm=sig_alg,
                       digest_algorithm="sha256",
                       c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    signed_assertion = signer.sign(a, key=key_pem, cert=cert_pem, reference_uri="_a1")
    # verify with signxml itself as a sanity check
    XMLVerifier().verify(deepcopy(signed_assertion), x509_cert=cert_pem)

    resp = response_wrap(deepcopy(signed_assertion))
    signed_resp_bytes = etree.tostring(resp)
    write(f"signed_assertion_{tag}.xml", etree.tostring(signed_assertion))
    write(f"signed_response_{tag}.xml", signed_resp_bytes)

    # base64 (POST binding)
    write(f"signed_response_{tag}.b64", base64.b64encode(signed_resp_bytes))
    # base64 + raw DEFLATE (redirect binding)
    import zlib
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    deflated = co.compress(signed_resp_bytes) + co.flush()
    write(f"signed_response_{tag}.deflate.b64", base64.b64encode(deflated))

    if tag == "rsa":
        # --- TAMPERED: change an attribute value after signing -> digest mismatch ---
        tampered = etree.fromstring(signed_resp_bytes)
        for av in tampered.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID"):
            av.text = "attacker@evil.com"
            break
        write("tampered_response_rsa.xml", etree.tostring(tampered))

        # --- XSW: duplicate assertion (multiple-assertions) ---
        xsw = etree.fromstring(signed_resp_bytes)
        orig = xsw.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        evil = deepcopy(orig)
        # strip the signature from the evil copy, change subject + ID
        for s in evil.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
            evil.remove(s)
        evil.set("ID", "_evil1")
        for nid in evil.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID"):
            nid.text = "attacker@evil.com"
        # XSW3: evil assertion is a sibling placed BEFORE the signed one
        xsw.insert(list(xsw).index(orig), evil)
        write("xsw3_response_rsa.xml", etree.tostring(xsw))

        # --- comment-splitting NameID ---
        cs = etree.fromstring(signed_resp_bytes)
        for nid in cs.iter("{urn:oasis:names:tc:SAML:2.0:assertion}NameID"):
            nid.text = "admin@example.com"
            nid.append(etree.Comment("x"))
            nid[-1].tail = "evil.com"
            break
        write("comment_splice_rsa.xml", etree.tostring(cs))

# --- An unsigned plain response (no signature) ---
a = etree.fromstring(assertion_xml().encode())
resp = response_wrap(a)
write("unsigned_response.xml", etree.tostring(resp))

# --- AuthnRequest (redirect binding source) ---
areq = """<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_areq1" Version="2.0" IssueInstant="2026-06-01T12:00:00Z" Destination="https://idp.example.com/sso"><saml:Issuer>https://sp.example.com</saml:Issuer></samlp:AuthnRequest>"""
write("authnrequest.xml", areq)
import zlib
co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
write("authnrequest.deflate.b64", base64.b64encode(co.compress(areq.encode()) + co.flush()))

# --- XXE / billion laughs / DTD hostile inputs ---
write("xxe.xml", """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Assertion>""")
write("billion_laughs.xml", """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&lol3;</saml:Assertion>""")

print("DONE")

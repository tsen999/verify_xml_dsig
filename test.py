"""verify XML signature"""

import logging
from lxml import etree
from signxml.verifier import XMLVerifier, SignatureConfiguration
from signxml.algorithms import DigestAlgorithm, SignatureMethod

logging.basicConfig(encoding="utf-8", level=logging.ERROR)


def validate_xml(file):
    """verify XML signature"""

    xml_data = None

    with open(file, "rb") as fh:
        xml_data = fh.read()
        x = etree.XML(xml_data)
        el = x.find(
            ".//ns:X509Certificate",
            namespaces={"ns": "http://www.w3.org/2000/09/xmldsig#"},
        )
        cert = el.text

    verifier = XMLVerifier()
    verifier.excise_empty_xmlns_declarations = True

    assertion_data = verifier.verify(
        xml_data,
        x509_cert=cert,
        expect_config=SignatureConfiguration(
            signature_methods=frozenset(
                {SignatureMethod.RSA_SHA1, SignatureMethod.RSA_SHA256}
            ),
            digest_algorithms=frozenset({DigestAlgorithm.SHA1, DigestAlgorithm.SHA256}),
        ),
    ).signed_xml
    s = etree.tostring(assertion_data)
    print(s)


validate_xml("xml-to-verify.xml")

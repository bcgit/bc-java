package org.bouncycastle.cbor.c509;

/**
 * The media types registered for C509 structures, Section 8.18 of
 * draft-ietf-cose-cbor-encoded-cert-20.
 */
public final class C509MediaTypes
{
    /** A C509Certificate structure. */
    public static final String CERTIFICATE = "application/cose-c509-cert+cbor";
    /** A COSE_C509 structure - one certificate or a bag or chain of them. */
    public static final String COSE_C509 = "application/cose-c509+cbor";
    /** A C509CertificationRequest structure. */
    public static final String CERTIFICATION_REQUEST = "application/cose-c509-pkcs10+cbor";
    /** A C509CertificationRequestTemplate structure. */
    public static final String CERTIFICATION_REQUEST_TEMPLATE = "application/cose-c509-crtemplate+cbor";
    /** A C509PrivateKey structure. */
    public static final String PRIVATE_KEY = "application/cose-c509-privkey+cbor";
    /** A C509PEM structure. */
    public static final String PEM = "application/cose-c509-pem+cbor";

    private C509MediaTypes()
    {
    }
}

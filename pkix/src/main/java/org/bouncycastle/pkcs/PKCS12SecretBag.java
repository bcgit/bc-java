package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.SecretBag;

/**
 * Wrapper around the RFC 7292 {@link SecretBag} ASN.1 structure used by the
 * PKCS#12 secretBag bag type.
 */
public class PKCS12SecretBag
{
    private final SecretBag secretBag;

    public PKCS12SecretBag(SecretBag secretBag)
    {
        this.secretBag = secretBag;
    }

    /**
     * Return the underlying ASN.1 structure for this secret bag.
     */
    public SecretBag toASN1Structure()
    {
        return secretBag;
    }

    /**
     * Return the OID identifying the type of the secret.
     */
    public ASN1ObjectIdentifier getSecretTypeId()
    {
        return secretBag.getSecretTypeId();
    }

    /**
     * Return the secret value associated with this bag.
     */
    public ASN1Encodable getSecretValue()
    {
        return secretBag.getSecretValue();
    }
}

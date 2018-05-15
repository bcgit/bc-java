package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Base class for PBKDF configs.
 */
public abstract class PBKDFConfig
{
    private final ASN1ObjectIdentifier algorithm;

    protected PBKDFConfig(ASN1ObjectIdentifier algorithm)
    {
        this.algorithm = algorithm;
    }

    public ASN1ObjectIdentifier getAlgorithm()
    {
        return algorithm;
    }
}

package org.bouncycastle.crypto.params;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class ECGOST3410Parameters
    extends ECNamedDomainParameters
{
    private final ASN1ObjectIdentifier  publicKeyParamSet;
    private final ASN1ObjectIdentifier  digestParamSet;
    private final ASN1ObjectIdentifier  encryptionParamSet;

    public ECGOST3410Parameters(ECNamedDomainParameters ecParameters, ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet)
    {
        this(ecParameters, publicKeyParamSet, digestParamSet, null);
    }

    public ECGOST3410Parameters(ECNamedDomainParameters ecParameters, ASN1ObjectIdentifier publicKeyParamSet, ASN1ObjectIdentifier digestParamSet, ASN1ObjectIdentifier encryptionParamSet)
    {
        super(ecParameters.getName(), ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH(), ecParameters.getSeed());

        this.publicKeyParamSet = publicKeyParamSet;
        this.digestParamSet = digestParamSet;
        this.encryptionParamSet = encryptionParamSet;
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet()
    {
        return publicKeyParamSet;
    }

    public ASN1ObjectIdentifier getDigestParamSet()
    {
        return digestParamSet;
    }

    public ASN1ObjectIdentifier getEncryptionParamSet()
    {
        return encryptionParamSet;
    }
}

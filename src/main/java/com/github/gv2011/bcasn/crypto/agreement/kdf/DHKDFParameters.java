package com.github.gv2011.bcasn.crypto.agreement.kdf;

import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.crypto.DerivationParameters;

public class DHKDFParameters
    implements DerivationParameters
{
    private ASN1ObjectIdentifier algorithm;
    private int keySize;
    private byte[] z;
    private byte[] extraInfo;

    public DHKDFParameters(
        ASN1ObjectIdentifier algorithm,
        int keySize,
        byte[] z)
    {
        this(algorithm, keySize, z, null);
    }

    public DHKDFParameters(
        ASN1ObjectIdentifier algorithm,
        int keySize,
        byte[] z,
        byte[] extraInfo)
    {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.z = z;
        this.extraInfo = extraInfo;
    }

    public ASN1ObjectIdentifier getAlgorithm()
    {
        return algorithm;
    }

    public int getKeySize()
    {
        return keySize;
    }

    public byte[] getZ()
    {
        return z;
    }

    public byte[] getExtraInfo()
    {
        return extraInfo;
    }
}

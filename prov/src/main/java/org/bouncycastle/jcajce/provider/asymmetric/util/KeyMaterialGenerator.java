package org.bouncycastle.jcajce.provider.asymmetric.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(ASN1ObjectIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}

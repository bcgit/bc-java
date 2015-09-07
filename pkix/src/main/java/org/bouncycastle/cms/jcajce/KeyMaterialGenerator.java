package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(ASN1ObjectIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}

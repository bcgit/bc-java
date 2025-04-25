package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.tls.SignatureScheme;

public class PQCUtil
{
    public static ASN1ObjectIdentifier getMLDSAObjectidentifier(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.DRAFT_mldsa44:
            return NISTObjectIdentifiers.id_ml_dsa_44;
        case SignatureScheme.DRAFT_mldsa65:
            return NISTObjectIdentifiers.id_ml_dsa_65;
        case SignatureScheme.DRAFT_mldsa87:
            return NISTObjectIdentifiers.id_ml_dsa_87;
        default:
            throw new IllegalArgumentException();
        }
    }

    public static int getMLDSASignatureScheme(MLDSAParameters parameters)
    {
        if (MLDSAParameters.ml_dsa_44 == parameters)
        {
            return SignatureScheme.DRAFT_mldsa44;
        }
        if (MLDSAParameters.ml_dsa_65 == parameters)
        {
            return SignatureScheme.DRAFT_mldsa65;
        }
        if (MLDSAParameters.ml_dsa_87 == parameters)
        {
            return SignatureScheme.DRAFT_mldsa87;
        }
        throw new IllegalArgumentException();
    }

    public static boolean supportsMLDSA(AlgorithmIdentifier pubKeyAlgID, ASN1ObjectIdentifier mlDsaAlgOid)
    {
        return pubKeyAlgID.getAlgorithm().equals(mlDsaAlgOid)
            && pubKeyAlgID.getParameters() == null;
    }
}

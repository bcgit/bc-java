package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.tls.SignatureScheme;

public class PQCUtil
{
    public static ASN1ObjectIdentifier getMLDSAObjectidentifier(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.mldsa44:
            return NISTObjectIdentifiers.id_ml_dsa_44;
        case SignatureScheme.mldsa65:
            return NISTObjectIdentifiers.id_ml_dsa_65;
        case SignatureScheme.mldsa87:
            return NISTObjectIdentifiers.id_ml_dsa_87;
        default:
            throw new IllegalArgumentException();
        }
    }

    public static int getMLDSASignatureScheme(MLDSAParameters parameters)
    {
        if (MLDSAParameters.ml_dsa_44 == parameters)
        {
            return SignatureScheme.mldsa44;
        }
        if (MLDSAParameters.ml_dsa_65 == parameters)
        {
            return SignatureScheme.mldsa65;
        }
        if (MLDSAParameters.ml_dsa_87 == parameters)
        {
            return SignatureScheme.mldsa87;
        }
        throw new IllegalArgumentException();
    }

    public static ASN1ObjectIdentifier getSLHDSAObjectidentifier(int signatureScheme)
    {
        switch (signatureScheme)
        {
        case SignatureScheme.DRAFT_slhdsa_sha2_128s:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_128s;
        case SignatureScheme.DRAFT_slhdsa_sha2_128f:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_128f;
        case SignatureScheme.DRAFT_slhdsa_sha2_192s:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_192s;
        case SignatureScheme.DRAFT_slhdsa_sha2_192f:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_192f;
        case SignatureScheme.DRAFT_slhdsa_sha2_256s:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_256s;
        case SignatureScheme.DRAFT_slhdsa_sha2_256f:
            return NISTObjectIdentifiers.id_slh_dsa_sha2_256f;
        case SignatureScheme.DRAFT_slhdsa_shake_128s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_128s;
        case SignatureScheme.DRAFT_slhdsa_shake_128f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_128f;
        case SignatureScheme.DRAFT_slhdsa_shake_192s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_192s;
        case SignatureScheme.DRAFT_slhdsa_shake_192f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_192f;
        case SignatureScheme.DRAFT_slhdsa_shake_256s:
            return NISTObjectIdentifiers.id_slh_dsa_shake_256s;
        case SignatureScheme.DRAFT_slhdsa_shake_256f:
            return NISTObjectIdentifiers.id_slh_dsa_shake_256f;
        default:
            throw new IllegalArgumentException();
        }
    }

    public static int getSLHDSASignatureScheme(SLHDSAParameters parameters)
    {
        if (SLHDSAParameters.sha2_128s == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_sha2_128s;
        }
        if (SLHDSAParameters.sha2_128f == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_sha2_128f;
        }
        if (SLHDSAParameters.sha2_192s == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_sha2_192s;
        }
        if (SLHDSAParameters.sha2_192f == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_sha2_192f;
        }
        if (SLHDSAParameters.sha2_256s == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_sha2_256s;
        }
        if (SLHDSAParameters.sha2_256f == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_sha2_256f;
        }
        if (SLHDSAParameters.shake_128s == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_shake_128s;
        }
        if (SLHDSAParameters.shake_128f == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_shake_128f;
        }
        if (SLHDSAParameters.shake_192s == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_shake_192s;
        }
        if (SLHDSAParameters.shake_192f == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_shake_192f;
        }
        if (SLHDSAParameters.shake_256s == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_shake_256s;
        }
        if (SLHDSAParameters.shake_256f == parameters)
        {
            return SignatureScheme.DRAFT_slhdsa_shake_256f;
        }
        throw new IllegalArgumentException();
    }

    public static boolean supportsMLDSA(AlgorithmIdentifier pubKeyAlgID, ASN1ObjectIdentifier mlDsaAlgOid)
    {
        return hasOidWithNullParameters(pubKeyAlgID, mlDsaAlgOid);
    }

    public static boolean supportsSLHDSA(AlgorithmIdentifier pubKeyAlgID, ASN1ObjectIdentifier slhDsaAlgOid)
    {
        return hasOidWithNullParameters(pubKeyAlgID, slhDsaAlgOid);
    }

    private static boolean hasOidWithNullParameters(AlgorithmIdentifier algID, ASN1ObjectIdentifier algOid)
    {
        return algID.getAlgorithm().equals(algOid)
            && algID.getParameters() == null;
    }
}

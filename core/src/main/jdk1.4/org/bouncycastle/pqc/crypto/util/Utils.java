package org.bouncycastle.pqc.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSKeyParameters;
import org.bouncycastle.util.Integers;

class Utils
{
   static final AlgorithmIdentifier AlgID_qTESLA_p_I = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_I);
    static final AlgorithmIdentifier AlgID_qTESLA_p_III = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_III);

    static final AlgorithmIdentifier SPHINCS_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256);
    static final AlgorithmIdentifier SPHINCS_SHA512_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256);

    static final AlgorithmIdentifier XMSS_SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    static final AlgorithmIdentifier XMSS_SHA512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
    static final AlgorithmIdentifier XMSS_SHAKE128 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
    static final AlgorithmIdentifier XMSS_SHAKE256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);

    static final Map categories = new HashMap();

    static
    {
        categories.put(PQCObjectIdentifiers.qTESLA_p_I, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_I));
        categories.put(PQCObjectIdentifiers.qTESLA_p_III, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_III));
    }

    static int qTeslaLookupSecurityCategory(AlgorithmIdentifier algorithm)
    {
        return ((Integer)categories.get(algorithm.getAlgorithm())).intValue();
    }

    static AlgorithmIdentifier qTeslaLookupAlgID(int securityCategory)
    {
        switch (securityCategory)
        {
        case QTESLASecurityCategory.PROVABLY_SECURE_I:
            return AlgID_qTESLA_p_I;
        case QTESLASecurityCategory.PROVABLY_SECURE_III:
            return AlgID_qTESLA_p_III;
        default:
            throw new IllegalArgumentException("unknown security category: " + securityCategory);
        }
    }

    static AlgorithmIdentifier sphincs256LookupTreeAlgID(String treeDigest)
    {
        if (treeDigest.equals(SPHINCSKeyParameters.SHA3_256))
        {
            return SPHINCS_SHA3_256;
        }
        else if (treeDigest.equals(SPHINCSKeyParameters.SHA512_256))
        {
            return SPHINCS_SHA512_256;
        }
        else
        {
            throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
        }
    }

    static String sphincs256LookupTreeAlgName(SPHINCS256KeyParams keyParams)
    {
        AlgorithmIdentifier treeDigest = keyParams.getTreeDigest();

        if (treeDigest.getAlgorithm().equals(SPHINCS_SHA3_256.getAlgorithm()))
        {
            return SPHINCSKeyParameters.SHA3_256;
        }
        else if (treeDigest.getAlgorithm().equals(SPHINCS_SHA512_256.getAlgorithm()))
        {
            return SPHINCSKeyParameters.SHA512_256;
        }
        else
        {
            throw new IllegalArgumentException("unknown tree digest: " + treeDigest.getAlgorithm());
        }
    }

    static Digest getDigest(ASN1ObjectIdentifier oid)
    {
        if (oid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return new SHA256Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return new SHA512Digest();
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake128))
        {
            return new SHAKEDigest(128);
        }
        if (oid.equals(NISTObjectIdentifiers.id_shake256))
        {
            return new SHAKEDigest(256);
        }

        throw new IllegalArgumentException("unrecognized digest OID: " + oid);
    }
}

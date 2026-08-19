package org.bouncycastle.pqc.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.legacy.bike.BIKEParameters;
import org.bouncycastle.pqc.legacy.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSKeyParameters;
import org.bouncycastle.util.Integers;

class Utils
{
    static final AlgorithmIdentifier AlgID_qTESLA_p_I = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_I);
    static final AlgorithmIdentifier AlgID_qTESLA_p_III = new AlgorithmIdentifier(PQCObjectIdentifiers.qTESLA_p_III);

    static final AlgorithmIdentifier SPHINCS_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256);
    static final AlgorithmIdentifier SPHINCS_SHA512_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256);


    static final Map categories = new HashMap();


    static final Map saberOids = new HashMap();
    static final Map saberParams = new HashMap();


    static final Map sikeOids = new HashMap();
    static final Map sikeParams = new HashMap();

    static final Map ntruOids = new HashMap();
    static final Map ntruParams = new HashMap();

    static final Map falconOids = new HashMap();
    static final Map falconParams = new HashMap();

    static final Map ntruprimeOids = new HashMap();
    static final Map ntruprimeParams = new HashMap();

    static final Map sntruprimeOids = new HashMap();
    static final Map sntruprimeParams = new HashMap();

    static final Map dilithiumOids = new HashMap();
    static final Map dilithiumParams = new HashMap();

    static final Map bikeOids = new HashMap();
    static final Map bikeParams = new HashMap();

    static final Map hqcOids = new HashMap();
    static final Map hqcParams = new HashMap();


    static
    {



        saberOids.put(SABERParameters.lightsaberkem128r3, BCObjectIdentifiers.lightsaberkem128r3);
        saberOids.put(SABERParameters.saberkem128r3, BCObjectIdentifiers.saberkem128r3);
        saberOids.put(SABERParameters.firesaberkem128r3, BCObjectIdentifiers.firesaberkem128r3);
        saberOids.put(SABERParameters.lightsaberkem192r3, BCObjectIdentifiers.lightsaberkem192r3);
        saberOids.put(SABERParameters.saberkem192r3, BCObjectIdentifiers.saberkem192r3);
        saberOids.put(SABERParameters.firesaberkem192r3, BCObjectIdentifiers.firesaberkem192r3);
        saberOids.put(SABERParameters.lightsaberkem256r3, BCObjectIdentifiers.lightsaberkem256r3);
        saberOids.put(SABERParameters.saberkem256r3, BCObjectIdentifiers.saberkem256r3);
        saberOids.put(SABERParameters.firesaberkem256r3, BCObjectIdentifiers.firesaberkem256r3);
        saberOids.put(SABERParameters.ulightsaberkemr3, BCObjectIdentifiers.ulightsaberkemr3);
        saberOids.put(SABERParameters.usaberkemr3, BCObjectIdentifiers.usaberkemr3);
        saberOids.put(SABERParameters.ufiresaberkemr3, BCObjectIdentifiers.ufiresaberkemr3);
        saberOids.put(SABERParameters.lightsaberkem90sr3, BCObjectIdentifiers.lightsaberkem90sr3);
        saberOids.put(SABERParameters.saberkem90sr3, BCObjectIdentifiers.saberkem90sr3);
        saberOids.put(SABERParameters.firesaberkem90sr3, BCObjectIdentifiers.firesaberkem90sr3);
        saberOids.put(SABERParameters.ulightsaberkem90sr3, BCObjectIdentifiers.ulightsaberkem90sr3);
        saberOids.put(SABERParameters.usaberkem90sr3, BCObjectIdentifiers.usaberkem90sr3);
        saberOids.put(SABERParameters.ufiresaberkem90sr3, BCObjectIdentifiers.ufiresaberkem90sr3);

        saberParams.put(BCObjectIdentifiers.lightsaberkem128r3, SABERParameters.lightsaberkem128r3);
        saberParams.put(BCObjectIdentifiers.saberkem128r3, SABERParameters.saberkem128r3);
        saberParams.put(BCObjectIdentifiers.firesaberkem128r3, SABERParameters.firesaberkem128r3);
        saberParams.put(BCObjectIdentifiers.lightsaberkem192r3, SABERParameters.lightsaberkem192r3);
        saberParams.put(BCObjectIdentifiers.saberkem192r3, SABERParameters.saberkem192r3);
        saberParams.put(BCObjectIdentifiers.firesaberkem192r3, SABERParameters.firesaberkem192r3);
        saberParams.put(BCObjectIdentifiers.lightsaberkem256r3, SABERParameters.lightsaberkem256r3);
        saberParams.put(BCObjectIdentifiers.saberkem256r3, SABERParameters.saberkem256r3);
        saberParams.put(BCObjectIdentifiers.firesaberkem256r3, SABERParameters.firesaberkem256r3);
        saberParams.put(BCObjectIdentifiers.ulightsaberkemr3, SABERParameters.ulightsaberkemr3);
        saberParams.put(BCObjectIdentifiers.usaberkemr3, SABERParameters.usaberkemr3);
        saberParams.put(BCObjectIdentifiers.ufiresaberkemr3, SABERParameters.ufiresaberkemr3);
        saberParams.put(BCObjectIdentifiers.lightsaberkem90sr3, SABERParameters.lightsaberkem90sr3);
        saberParams.put(BCObjectIdentifiers.saberkem90sr3, SABERParameters.saberkem90sr3);
        saberParams.put(BCObjectIdentifiers.firesaberkem90sr3, SABERParameters.firesaberkem90sr3);
        saberParams.put(BCObjectIdentifiers.ulightsaberkem90sr3, SABERParameters.ulightsaberkem90sr3);
        saberParams.put(BCObjectIdentifiers.usaberkem90sr3, SABERParameters.usaberkem90sr3);
        saberParams.put(BCObjectIdentifiers.ufiresaberkem90sr3, SABERParameters.ufiresaberkem90sr3);


        falconOids.put(FalconParameters.falcon_512, BCObjectIdentifiers.falcon_512);
        falconOids.put(FalconParameters.falcon_1024, BCObjectIdentifiers.falcon_1024);

        falconParams.put(BCObjectIdentifiers.falcon_512, FalconParameters.falcon_512);
        falconParams.put(BCObjectIdentifiers.falcon_1024, FalconParameters.falcon_1024);

        dilithiumOids.put(DilithiumParameters.dilithium2, BCObjectIdentifiers.dilithium2);
        dilithiumOids.put(DilithiumParameters.dilithium3, BCObjectIdentifiers.dilithium3);
        dilithiumOids.put(DilithiumParameters.dilithium5, BCObjectIdentifiers.dilithium5);

        dilithiumParams.put(BCObjectIdentifiers.dilithium2, DilithiumParameters.dilithium2);
        dilithiumParams.put(BCObjectIdentifiers.dilithium3, DilithiumParameters.dilithium3);
        dilithiumParams.put(BCObjectIdentifiers.dilithium5, DilithiumParameters.dilithium5);

        bikeParams.put(BCObjectIdentifiers.bike128, BIKEParameters.bike128);
        bikeParams.put(BCObjectIdentifiers.bike192, BIKEParameters.bike192);
        bikeParams.put(BCObjectIdentifiers.bike256, BIKEParameters.bike256);

        bikeOids.put(BIKEParameters.bike128, BCObjectIdentifiers.bike128);
        bikeOids.put(BIKEParameters.bike192, BCObjectIdentifiers.bike192);
        bikeOids.put(BIKEParameters.bike256, BCObjectIdentifiers.bike256);

        hqcParams.put(BCObjectIdentifiers.hqc128, HQCParameters.hqc128);
        hqcParams.put(BCObjectIdentifiers.hqc192, HQCParameters.hqc192);
        hqcParams.put(BCObjectIdentifiers.hqc256, HQCParameters.hqc256);

        hqcOids.put(HQCParameters.hqc128, BCObjectIdentifiers.hqc128);
        hqcOids.put(HQCParameters.hqc192, BCObjectIdentifiers.hqc192);
        hqcOids.put(HQCParameters.hqc256, BCObjectIdentifiers.hqc256);

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

    public static AlgorithmIdentifier getAlgorithmIdentifier(String digestName)
    {
        if (digestName.equals("SHA-1"))
        {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        }
        if (digestName.equals("SHA-224"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224);
        }
        if (digestName.equals("SHA-256"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        if (digestName.equals("SHA-384"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        if (digestName.equals("SHA-512"))
        {
            return new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }

    public static String getDigestName(ASN1ObjectIdentifier digestOid)
    {
        if (digestOid.equals(OIWObjectIdentifiers.idSHA1))
        {
            return "SHA-1";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha224))
        {
            return "SHA-224";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha256))
        {
            return "SHA-256";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha384))
        {
            return "SHA-384";
        }
        if (digestOid.equals(NISTObjectIdentifiers.id_sha512))
        {
            return "SHA-512";
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestOid);
    }

    static ASN1ObjectIdentifier saberOidLookup(SABERParameters params)
    {
        return (ASN1ObjectIdentifier)saberOids.get(params);
    }

    static SABERParameters saberParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (SABERParameters)saberParams.get(oid);
    }

    static ASN1ObjectIdentifier falconOidLookup(FalconParameters params)
    {
        return (ASN1ObjectIdentifier)falconOids.get(params);
    }

    static FalconParameters falconParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (FalconParameters)falconParams.get(oid);
    }


    static ASN1ObjectIdentifier dilithiumOidLookup(DilithiumParameters params)
    {
        return (ASN1ObjectIdentifier)dilithiumOids.get(params);
    }

    static DilithiumParameters dilithiumParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (DilithiumParameters)dilithiumParams.get(oid);
    }

    static ASN1ObjectIdentifier bikeOidLookup(BIKEParameters params)
    {
        return (ASN1ObjectIdentifier)bikeOids.get(params);
    }

    static BIKEParameters bikeParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (BIKEParameters)bikeParams.get(oid);
    }

    static ASN1ObjectIdentifier hqcOidLookup(HQCParameters params)
    {
        return (ASN1ObjectIdentifier)hqcOids.get(params);
    }

    static HQCParameters hqcParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (HQCParameters)hqcParams.get(oid);
    }
}

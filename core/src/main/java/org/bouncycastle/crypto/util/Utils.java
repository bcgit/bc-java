package org.bouncycastle.crypto.util;

import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyParameters;

class Utils
{
    static final AlgorithmIdentifier SPHINCS_SHA3_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256);
    static final AlgorithmIdentifier SPHINCS_SHA512_256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512_256);

    static final AlgorithmIdentifier XMSS_SHA256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    static final AlgorithmIdentifier XMSS_SHA512 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512);
    static final AlgorithmIdentifier XMSS_SHAKE128 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake128);
    static final AlgorithmIdentifier XMSS_SHAKE256 = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);

    static final Map frodoOids = new HashMap();
    static final Map frodoParams = new HashMap();

    static final Map saberOids = new HashMap();
    static final Map saberParams = new HashMap();

    static final Map mcElieceOids = new HashMap();
    static final Map mcElieceParams = new HashMap();

    static final Map sphincsPlusOids = new HashMap();
    static final Map sphincsPlusParams = new HashMap();

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

    static final Map hqcOids = new HashMap();
    static final Map hqcParams = new HashMap();

    static final Map mlkemOids = new HashMap<ASN1ObjectIdentifier, MLKEMParameters>();
    static final Map mlkemParams = new HashMap<MLKEMParameters, ASN1ObjectIdentifier>();

    static final Map mldsaOids = new HashMap<ASN1ObjectIdentifier, MLDSAParameters>();
    static final Map mldsaParams = new HashMap<MLDSAParameters, ASN1ObjectIdentifier>();

    static final Map slhdsaOids = new HashMap<ASN1ObjectIdentifier, SLHDSAParameters>();
    static final Map slhdsaParams = new HashMap<SLHDSAParameters, ASN1ObjectIdentifier>();

    static final Map mayoOids = new HashMap<ASN1ObjectIdentifier, MayoParameters>();
    static final Map mayoParams = new HashMap<MayoParameters, ASN1ObjectIdentifier>();

    static final Map snovaOids = new HashMap<ASN1ObjectIdentifier, SnovaParameters>();
    static final Map snovaParams = new HashMap<SnovaParameters, ASN1ObjectIdentifier>();

    static final Map ntruPlusOids = new HashMap<ASN1ObjectIdentifier, NTRUPlusParameters>();
    static final Map ntruPlusParams = new HashMap<NTRUPlusParameters, ASN1ObjectIdentifier>();

    static
    {
        mcElieceOids.put(CMCEParameters.mceliece348864r3, BCObjectIdentifiers.mceliece348864_r3);
        mcElieceOids.put(CMCEParameters.mceliece348864fr3, BCObjectIdentifiers.mceliece348864f_r3);
        mcElieceOids.put(CMCEParameters.mceliece460896r3, BCObjectIdentifiers.mceliece460896_r3);
        mcElieceOids.put(CMCEParameters.mceliece460896fr3, BCObjectIdentifiers.mceliece460896f_r3);
        mcElieceOids.put(CMCEParameters.mceliece6688128r3, BCObjectIdentifiers.mceliece6688128_r3);
        mcElieceOids.put(CMCEParameters.mceliece6688128fr3, BCObjectIdentifiers.mceliece6688128f_r3);
        mcElieceOids.put(CMCEParameters.mceliece6960119r3, BCObjectIdentifiers.mceliece6960119_r3);
        mcElieceOids.put(CMCEParameters.mceliece6960119fr3, BCObjectIdentifiers.mceliece6960119f_r3);
        mcElieceOids.put(CMCEParameters.mceliece8192128r3, BCObjectIdentifiers.mceliece8192128_r3);
        mcElieceOids.put(CMCEParameters.mceliece8192128fr3, BCObjectIdentifiers.mceliece8192128f_r3);

        mcElieceParams.put(BCObjectIdentifiers.mceliece348864_r3, CMCEParameters.mceliece348864r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece348864f_r3, CMCEParameters.mceliece348864fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece460896_r3, CMCEParameters.mceliece460896r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece460896f_r3, CMCEParameters.mceliece460896fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6688128_r3, CMCEParameters.mceliece6688128r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6688128f_r3, CMCEParameters.mceliece6688128fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6960119_r3, CMCEParameters.mceliece6960119r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece6960119f_r3, CMCEParameters.mceliece6960119fr3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece8192128_r3, CMCEParameters.mceliece8192128r3);
        mcElieceParams.put(BCObjectIdentifiers.mceliece8192128f_r3, CMCEParameters.mceliece8192128fr3);

        frodoOids.put(FrodoParameters.frodokem640aes, BCObjectIdentifiers.frodokem640aes);
        frodoOids.put(FrodoParameters.frodokem640shake, BCObjectIdentifiers.frodokem640shake);
        frodoOids.put(FrodoParameters.frodokem976aes, BCObjectIdentifiers.frodokem976aes);
        frodoOids.put(FrodoParameters.frodokem976shake, BCObjectIdentifiers.frodokem976shake);
        frodoOids.put(FrodoParameters.frodokem1344aes, BCObjectIdentifiers.frodokem1344aes);
        frodoOids.put(FrodoParameters.frodokem1344shake, BCObjectIdentifiers.frodokem1344shake);

        frodoParams.put(BCObjectIdentifiers.frodokem640aes, FrodoParameters.frodokem640aes);
        frodoParams.put(BCObjectIdentifiers.frodokem640shake, FrodoParameters.frodokem640shake);
        frodoParams.put(BCObjectIdentifiers.frodokem976aes, FrodoParameters.frodokem976aes);
        frodoParams.put(BCObjectIdentifiers.frodokem976shake, FrodoParameters.frodokem976shake);
        frodoParams.put(BCObjectIdentifiers.frodokem1344aes, FrodoParameters.frodokem1344aes);
        frodoParams.put(BCObjectIdentifiers.frodokem1344shake, FrodoParameters.frodokem1344shake);

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

        ntruOids.put(NTRUParameters.ntruhps2048509, BCObjectIdentifiers.ntruhps2048509);
        ntruOids.put(NTRUParameters.ntruhps2048677, BCObjectIdentifiers.ntruhps2048677);
        ntruOids.put(NTRUParameters.ntruhps4096821, BCObjectIdentifiers.ntruhps4096821);
        ntruOids.put(NTRUParameters.ntruhps40961229, BCObjectIdentifiers.ntruhps40961229);
        ntruOids.put(NTRUParameters.ntruhrss701, BCObjectIdentifiers.ntruhrss701);
        ntruOids.put(NTRUParameters.ntruhrss1373, BCObjectIdentifiers.ntruhrss1373);

        ntruParams.put(BCObjectIdentifiers.ntruhps2048509, NTRUParameters.ntruhps2048509);
        ntruParams.put(BCObjectIdentifiers.ntruhps2048677, NTRUParameters.ntruhps2048677);
        ntruParams.put(BCObjectIdentifiers.ntruhps4096821, NTRUParameters.ntruhps4096821);
        ntruParams.put(BCObjectIdentifiers.ntruhps40961229, NTRUParameters.ntruhps40961229);
        ntruParams.put(BCObjectIdentifiers.ntruhrss701, NTRUParameters.ntruhrss701);
        ntruParams.put(BCObjectIdentifiers.ntruhrss1373, NTRUParameters.ntruhrss1373);

        falconOids.put(FalconParameters.falcon_512, BCObjectIdentifiers.falcon_512);
        falconOids.put(FalconParameters.falcon_1024, BCObjectIdentifiers.falcon_1024);

        falconParams.put(BCObjectIdentifiers.falcon_512, FalconParameters.falcon_512);
        falconParams.put(BCObjectIdentifiers.falcon_1024, FalconParameters.falcon_1024);
        falconParams.put(BCObjectIdentifiers.old_falcon_512, FalconParameters.falcon_512);
        falconParams.put(BCObjectIdentifiers.old_falcon_1024, FalconParameters.falcon_1024);

        mlkemOids.put(MLKEMParameters.ml_kem_512, NISTObjectIdentifiers.id_alg_ml_kem_512);
        mlkemOids.put(MLKEMParameters.ml_kem_768, NISTObjectIdentifiers.id_alg_ml_kem_768);
        mlkemOids.put(MLKEMParameters.ml_kem_1024, NISTObjectIdentifiers.id_alg_ml_kem_1024);

        mlkemParams.put(NISTObjectIdentifiers.id_alg_ml_kem_512, MLKEMParameters.ml_kem_512);
        mlkemParams.put(NISTObjectIdentifiers.id_alg_ml_kem_768, MLKEMParameters.ml_kem_768);
        mlkemParams.put(NISTObjectIdentifiers.id_alg_ml_kem_1024, MLKEMParameters.ml_kem_1024);

        ntruprimeOids.put(NTRULPRimeParameters.ntrulpr653, BCObjectIdentifiers.ntrulpr653);
        ntruprimeOids.put(NTRULPRimeParameters.ntrulpr761, BCObjectIdentifiers.ntrulpr761);
        ntruprimeOids.put(NTRULPRimeParameters.ntrulpr857, BCObjectIdentifiers.ntrulpr857);
        ntruprimeOids.put(NTRULPRimeParameters.ntrulpr953, BCObjectIdentifiers.ntrulpr953);
        ntruprimeOids.put(NTRULPRimeParameters.ntrulpr1013, BCObjectIdentifiers.ntrulpr1013);
        ntruprimeOids.put(NTRULPRimeParameters.ntrulpr1277, BCObjectIdentifiers.ntrulpr1277);

        ntruprimeParams.put(BCObjectIdentifiers.ntrulpr653, NTRULPRimeParameters.ntrulpr653);
        ntruprimeParams.put(BCObjectIdentifiers.ntrulpr761, NTRULPRimeParameters.ntrulpr761);
        ntruprimeParams.put(BCObjectIdentifiers.ntrulpr857, NTRULPRimeParameters.ntrulpr857);
        ntruprimeParams.put(BCObjectIdentifiers.ntrulpr953, NTRULPRimeParameters.ntrulpr953);
        ntruprimeParams.put(BCObjectIdentifiers.ntrulpr1013, NTRULPRimeParameters.ntrulpr1013);
        ntruprimeParams.put(BCObjectIdentifiers.ntrulpr1277, NTRULPRimeParameters.ntrulpr1277);

        sntruprimeOids.put(SNTRUPrimeParameters.sntrup653, BCObjectIdentifiers.sntrup653);
        sntruprimeOids.put(SNTRUPrimeParameters.sntrup761, BCObjectIdentifiers.sntrup761);
        sntruprimeOids.put(SNTRUPrimeParameters.sntrup857, BCObjectIdentifiers.sntrup857);
        sntruprimeOids.put(SNTRUPrimeParameters.sntrup953, BCObjectIdentifiers.sntrup953);
        sntruprimeOids.put(SNTRUPrimeParameters.sntrup1013, BCObjectIdentifiers.sntrup1013);
        sntruprimeOids.put(SNTRUPrimeParameters.sntrup1277, BCObjectIdentifiers.sntrup1277);

        sntruprimeParams.put(BCObjectIdentifiers.sntrup653, SNTRUPrimeParameters.sntrup653);
        sntruprimeParams.put(BCObjectIdentifiers.sntrup761, SNTRUPrimeParameters.sntrup761);
        sntruprimeParams.put(BCObjectIdentifiers.sntrup857, SNTRUPrimeParameters.sntrup857);
        sntruprimeParams.put(BCObjectIdentifiers.sntrup953, SNTRUPrimeParameters.sntrup953);
        sntruprimeParams.put(BCObjectIdentifiers.sntrup1013, SNTRUPrimeParameters.sntrup1013);
        sntruprimeParams.put(BCObjectIdentifiers.sntrup1277, SNTRUPrimeParameters.sntrup1277);

        mldsaOids.put(MLDSAParameters.ml_dsa_44, NISTObjectIdentifiers.id_ml_dsa_44);
        mldsaOids.put(MLDSAParameters.ml_dsa_65, NISTObjectIdentifiers.id_ml_dsa_65);
        mldsaOids.put(MLDSAParameters.ml_dsa_87, NISTObjectIdentifiers.id_ml_dsa_87);
        mldsaOids.put(MLDSAParameters.ml_dsa_44_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        mldsaOids.put(MLDSAParameters.ml_dsa_65_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        mldsaOids.put(MLDSAParameters.ml_dsa_87_with_sha512, NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);

        mldsaParams.put(NISTObjectIdentifiers.id_ml_dsa_44, MLDSAParameters.ml_dsa_44);
        mldsaParams.put(NISTObjectIdentifiers.id_ml_dsa_65, MLDSAParameters.ml_dsa_65);
        mldsaParams.put(NISTObjectIdentifiers.id_ml_dsa_87, MLDSAParameters.ml_dsa_87);
        mldsaParams.put(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, MLDSAParameters.ml_dsa_44_with_sha512);
        mldsaParams.put(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, MLDSAParameters.ml_dsa_65_with_sha512);
        mldsaParams.put(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, MLDSAParameters.ml_dsa_87_with_sha512);

        hqcParams.put(BCObjectIdentifiers.hqc128, HQCParameters.hqc128);
        hqcParams.put(BCObjectIdentifiers.hqc192, HQCParameters.hqc192);
        hqcParams.put(BCObjectIdentifiers.hqc256, HQCParameters.hqc256);

        hqcOids.put(HQCParameters.hqc128, BCObjectIdentifiers.hqc128);
        hqcOids.put(HQCParameters.hqc192, BCObjectIdentifiers.hqc192);
        hqcOids.put(HQCParameters.hqc256, BCObjectIdentifiers.hqc256);

        slhdsaOids.put(SLHDSAParameters.sha2_128s, NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        slhdsaOids.put(SLHDSAParameters.sha2_128f, NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        slhdsaOids.put(SLHDSAParameters.sha2_192s, NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        slhdsaOids.put(SLHDSAParameters.sha2_192f, NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        slhdsaOids.put(SLHDSAParameters.sha2_256s, NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        slhdsaOids.put(SLHDSAParameters.sha2_256f, NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        slhdsaOids.put(SLHDSAParameters.shake_128s, NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        slhdsaOids.put(SLHDSAParameters.shake_128f, NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        slhdsaOids.put(SLHDSAParameters.shake_192s, NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        slhdsaOids.put(SLHDSAParameters.shake_192f, NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        slhdsaOids.put(SLHDSAParameters.shake_256s, NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        slhdsaOids.put(SLHDSAParameters.shake_256f, NISTObjectIdentifiers.id_slh_dsa_shake_256f);

        slhdsaOids.put(SLHDSAParameters.sha2_128s_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        slhdsaOids.put(SLHDSAParameters.sha2_128f_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        slhdsaOids.put(SLHDSAParameters.sha2_192s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        slhdsaOids.put(SLHDSAParameters.sha2_192f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        slhdsaOids.put(SLHDSAParameters.sha2_256s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        slhdsaOids.put(SLHDSAParameters.sha2_256f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        slhdsaOids.put(SLHDSAParameters.shake_128s_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        slhdsaOids.put(SLHDSAParameters.shake_128f_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        slhdsaOids.put(SLHDSAParameters.shake_192s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        slhdsaOids.put(SLHDSAParameters.shake_192f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        slhdsaOids.put(SLHDSAParameters.shake_256s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
        slhdsaOids.put(SLHDSAParameters.shake_256f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);

        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, SLHDSAParameters.sha2_128s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, SLHDSAParameters.sha2_128f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, SLHDSAParameters.sha2_192s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, SLHDSAParameters.sha2_192f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, SLHDSAParameters.sha2_256s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, SLHDSAParameters.sha2_256f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_128s, SLHDSAParameters.shake_128s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_128f, SLHDSAParameters.shake_128f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_192s, SLHDSAParameters.shake_192s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_192f, SLHDSAParameters.shake_192f);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_256s, SLHDSAParameters.shake_256s);
        slhdsaParams.put(NISTObjectIdentifiers.id_slh_dsa_shake_256f, SLHDSAParameters.shake_256f);

        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, SLHDSAParameters.sha2_128s_with_sha256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, SLHDSAParameters.sha2_128f_with_sha256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, SLHDSAParameters.sha2_192s_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, SLHDSAParameters.sha2_192f_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, SLHDSAParameters.sha2_256s_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, SLHDSAParameters.sha2_256f_with_sha512);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, SLHDSAParameters.shake_128s_with_shake128);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, SLHDSAParameters.shake_128f_with_shake128);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, SLHDSAParameters.shake_192s_with_shake256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, SLHDSAParameters.shake_192f_with_shake256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, SLHDSAParameters.shake_256s_with_shake256);
        slhdsaParams.put(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, SLHDSAParameters.shake_256f_with_shake256);

        mayoOids.put(MayoParameters.mayo1, BCObjectIdentifiers.mayo1);
        mayoOids.put(MayoParameters.mayo2, BCObjectIdentifiers.mayo2);
        mayoOids.put(MayoParameters.mayo3, BCObjectIdentifiers.mayo3);
        mayoOids.put(MayoParameters.mayo5, BCObjectIdentifiers.mayo5);

        mayoParams.put(BCObjectIdentifiers.mayo1, MayoParameters.mayo1);
        mayoParams.put(BCObjectIdentifiers.mayo2, MayoParameters.mayo2);
        mayoParams.put(BCObjectIdentifiers.mayo3, MayoParameters.mayo3);
        mayoParams.put(BCObjectIdentifiers.mayo5, MayoParameters.mayo5);

        snovaOids.put(SnovaParameters.SNOVA_24_5_4_SSK, BCObjectIdentifiers.snova_24_5_4_ssk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_4_ESK, BCObjectIdentifiers.snova_24_5_4_esk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_4_SHAKE_SSK, BCObjectIdentifiers.snova_24_5_4_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_4_SHAKE_ESK, BCObjectIdentifiers.snova_24_5_4_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_5_SSK, BCObjectIdentifiers.snova_24_5_5_ssk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_5_ESK, BCObjectIdentifiers.snova_24_5_5_esk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_5_SHAKE_SSK, BCObjectIdentifiers.snova_24_5_5_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_24_5_5_SHAKE_ESK, BCObjectIdentifiers.snova_24_5_5_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_25_8_3_SSK, BCObjectIdentifiers.snova_25_8_3_ssk);
        snovaOids.put(SnovaParameters.SNOVA_25_8_3_ESK, BCObjectIdentifiers.snova_25_8_3_esk);
        snovaOids.put(SnovaParameters.SNOVA_25_8_3_SHAKE_SSK, BCObjectIdentifiers.snova_25_8_3_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_25_8_3_SHAKE_ESK, BCObjectIdentifiers.snova_25_8_3_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_29_6_5_SSK, BCObjectIdentifiers.snova_29_6_5_ssk);
        snovaOids.put(SnovaParameters.SNOVA_29_6_5_ESK, BCObjectIdentifiers.snova_29_6_5_esk);
        snovaOids.put(SnovaParameters.SNOVA_29_6_5_SHAKE_SSK, BCObjectIdentifiers.snova_29_6_5_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_29_6_5_SHAKE_ESK, BCObjectIdentifiers.snova_29_6_5_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_37_8_4_SSK, BCObjectIdentifiers.snova_37_8_4_ssk);
        snovaOids.put(SnovaParameters.SNOVA_37_8_4_ESK, BCObjectIdentifiers.snova_37_8_4_esk);
        snovaOids.put(SnovaParameters.SNOVA_37_8_4_SHAKE_SSK, BCObjectIdentifiers.snova_37_8_4_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_37_8_4_SHAKE_ESK, BCObjectIdentifiers.snova_37_8_4_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_37_17_2_SSK, BCObjectIdentifiers.snova_37_17_2_ssk);
        snovaOids.put(SnovaParameters.SNOVA_37_17_2_ESK, BCObjectIdentifiers.snova_37_17_2_esk);
        snovaOids.put(SnovaParameters.SNOVA_37_17_2_SHAKE_SSK, BCObjectIdentifiers.snova_37_17_2_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_37_17_2_SHAKE_ESK, BCObjectIdentifiers.snova_37_17_2_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_49_11_3_SSK, BCObjectIdentifiers.snova_49_11_3_ssk);
        snovaOids.put(SnovaParameters.SNOVA_49_11_3_ESK, BCObjectIdentifiers.snova_49_11_3_esk);
        snovaOids.put(SnovaParameters.SNOVA_49_11_3_SHAKE_SSK, BCObjectIdentifiers.snova_49_11_3_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_49_11_3_SHAKE_ESK, BCObjectIdentifiers.snova_49_11_3_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_56_25_2_SSK, BCObjectIdentifiers.snova_56_25_2_ssk);
        snovaOids.put(SnovaParameters.SNOVA_56_25_2_ESK, BCObjectIdentifiers.snova_56_25_2_esk);
        snovaOids.put(SnovaParameters.SNOVA_56_25_2_SHAKE_SSK, BCObjectIdentifiers.snova_56_25_2_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_56_25_2_SHAKE_ESK, BCObjectIdentifiers.snova_56_25_2_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_60_10_4_SSK, BCObjectIdentifiers.snova_60_10_4_ssk);
        snovaOids.put(SnovaParameters.SNOVA_60_10_4_ESK, BCObjectIdentifiers.snova_60_10_4_esk);
        snovaOids.put(SnovaParameters.SNOVA_60_10_4_SHAKE_SSK, BCObjectIdentifiers.snova_60_10_4_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_60_10_4_SHAKE_ESK, BCObjectIdentifiers.snova_60_10_4_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_66_15_3_SSK, BCObjectIdentifiers.snova_66_15_3_ssk);
        snovaOids.put(SnovaParameters.SNOVA_66_15_3_ESK, BCObjectIdentifiers.snova_66_15_3_esk);
        snovaOids.put(SnovaParameters.SNOVA_66_15_3_SHAKE_SSK, BCObjectIdentifiers.snova_66_15_3_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_66_15_3_SHAKE_ESK, BCObjectIdentifiers.snova_66_15_3_shake_esk);
        snovaOids.put(SnovaParameters.SNOVA_75_33_2_SSK, BCObjectIdentifiers.snova_75_33_2_ssk);
        snovaOids.put(SnovaParameters.SNOVA_75_33_2_ESK, BCObjectIdentifiers.snova_75_33_2_esk);
        snovaOids.put(SnovaParameters.SNOVA_75_33_2_SHAKE_SSK, BCObjectIdentifiers.snova_75_33_2_shake_ssk);
        snovaOids.put(SnovaParameters.SNOVA_75_33_2_SHAKE_ESK, BCObjectIdentifiers.snova_75_33_2_shake_esk);

        snovaParams.put(BCObjectIdentifiers.snova_24_5_4_ssk, SnovaParameters.SNOVA_24_5_4_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_4_esk, SnovaParameters.SNOVA_24_5_4_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_4_shake_ssk, SnovaParameters.SNOVA_24_5_4_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_4_shake_esk, SnovaParameters.SNOVA_24_5_4_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_5_ssk, SnovaParameters.SNOVA_24_5_5_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_5_esk, SnovaParameters.SNOVA_24_5_5_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_5_shake_ssk, SnovaParameters.SNOVA_24_5_5_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_24_5_5_shake_esk, SnovaParameters.SNOVA_24_5_5_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_25_8_3_ssk, SnovaParameters.SNOVA_25_8_3_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_25_8_3_esk, SnovaParameters.SNOVA_25_8_3_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_25_8_3_shake_ssk, SnovaParameters.SNOVA_25_8_3_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_25_8_3_shake_esk, SnovaParameters.SNOVA_25_8_3_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_29_6_5_ssk, SnovaParameters.SNOVA_29_6_5_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_29_6_5_esk, SnovaParameters.SNOVA_29_6_5_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_29_6_5_shake_ssk, SnovaParameters.SNOVA_29_6_5_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_29_6_5_shake_esk, SnovaParameters.SNOVA_29_6_5_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_37_8_4_ssk, SnovaParameters.SNOVA_37_8_4_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_37_8_4_esk, SnovaParameters.SNOVA_37_8_4_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_37_8_4_shake_ssk, SnovaParameters.SNOVA_37_8_4_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_37_8_4_shake_esk, SnovaParameters.SNOVA_37_8_4_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_37_17_2_ssk, SnovaParameters.SNOVA_37_17_2_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_37_17_2_esk, SnovaParameters.SNOVA_37_17_2_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_37_17_2_shake_ssk, SnovaParameters.SNOVA_37_17_2_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_37_17_2_shake_esk, SnovaParameters.SNOVA_37_17_2_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_49_11_3_ssk, SnovaParameters.SNOVA_49_11_3_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_49_11_3_esk, SnovaParameters.SNOVA_49_11_3_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_49_11_3_shake_ssk, SnovaParameters.SNOVA_49_11_3_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_49_11_3_shake_esk, SnovaParameters.SNOVA_49_11_3_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_56_25_2_ssk, SnovaParameters.SNOVA_56_25_2_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_56_25_2_esk, SnovaParameters.SNOVA_56_25_2_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_56_25_2_shake_ssk, SnovaParameters.SNOVA_56_25_2_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_56_25_2_shake_esk, SnovaParameters.SNOVA_56_25_2_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_60_10_4_ssk, SnovaParameters.SNOVA_60_10_4_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_60_10_4_esk, SnovaParameters.SNOVA_60_10_4_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_60_10_4_shake_ssk, SnovaParameters.SNOVA_60_10_4_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_60_10_4_shake_esk, SnovaParameters.SNOVA_60_10_4_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_66_15_3_ssk, SnovaParameters.SNOVA_66_15_3_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_66_15_3_esk, SnovaParameters.SNOVA_66_15_3_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_66_15_3_shake_ssk, SnovaParameters.SNOVA_66_15_3_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_66_15_3_shake_esk, SnovaParameters.SNOVA_66_15_3_SHAKE_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_75_33_2_ssk, SnovaParameters.SNOVA_75_33_2_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_75_33_2_esk, SnovaParameters.SNOVA_75_33_2_ESK);
        snovaParams.put(BCObjectIdentifiers.snova_75_33_2_shake_ssk, SnovaParameters.SNOVA_75_33_2_SHAKE_SSK);
        snovaParams.put(BCObjectIdentifiers.snova_75_33_2_shake_esk, SnovaParameters.SNOVA_75_33_2_SHAKE_ESK);

        ntruPlusParams.put(BCObjectIdentifiers.ntruPlus768, NTRUPlusParameters.ntruplus_kem_768);
        ntruPlusParams.put(BCObjectIdentifiers.ntruPlus864, NTRUPlusParameters.ntruplus_kem_864);
        ntruPlusParams.put(BCObjectIdentifiers.ntruPlus1152, NTRUPlusParameters.ntruplus_kem_1152);

        ntruPlusOids.put(NTRUPlusParameters.ntruplus_kem_768, BCObjectIdentifiers.ntruPlus768);
        ntruPlusOids.put(NTRUPlusParameters.ntruplus_kem_864, BCObjectIdentifiers.ntruPlus864);
        ntruPlusOids.put(NTRUPlusParameters.ntruplus_kem_1152, BCObjectIdentifiers.ntruPlus1152);
    }

    static ASN1ObjectIdentifier slhdsaOidLookup(SLHDSAParameters params)
    {
        return (ASN1ObjectIdentifier)slhdsaOids.get(params);
    }

    static SLHDSAParameters slhdsaParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (SLHDSAParameters)slhdsaParams.get(oid);
    }

    static AlgorithmIdentifier xmssLookupTreeAlgID(String treeDigest)
    {
        if (treeDigest.equals(XMSSKeyParameters.SHA_256))
        {
            return XMSS_SHA256;
        }
        else if (treeDigest.equals(XMSSKeyParameters.SHA_512))
        {
            return XMSS_SHA512;
        }
        else if (treeDigest.equals(XMSSKeyParameters.SHAKE128))
        {
            return XMSS_SHAKE128;
        }
        else if (treeDigest.equals(XMSSKeyParameters.SHAKE256))
        {
            return XMSS_SHAKE256;
        }
        else
        {
            throw new IllegalArgumentException("unknown tree digest: " + treeDigest);
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

    static ASN1ObjectIdentifier mcElieceOidLookup(CMCEParameters params)
    {
        return (ASN1ObjectIdentifier)mcElieceOids.get(params);
    }

    static CMCEParameters mcElieceParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (CMCEParameters)mcElieceParams.get(oid);
    }

    static ASN1ObjectIdentifier frodoOidLookup(FrodoParameters params)
    {
        return (ASN1ObjectIdentifier)frodoOids.get(params);
    }

    static FrodoParameters frodoParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (FrodoParameters)frodoParams.get(oid);
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

    static ASN1ObjectIdentifier ntruOidLookup(NTRUParameters params)
    {
        return (ASN1ObjectIdentifier)ntruOids.get(params);
    }

    static NTRUParameters ntruParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (NTRUParameters)ntruParams.get(oid);
    }

    static ASN1ObjectIdentifier mlkemOidLookup(MLKEMParameters params)
    {
        return (ASN1ObjectIdentifier)mlkemOids.get(params);
    }

    static MLKEMParameters mlkemParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (MLKEMParameters)mlkemParams.get(oid);
    }

    static ASN1ObjectIdentifier ntrulprimeOidLookup(NTRULPRimeParameters params)
    {
        return (ASN1ObjectIdentifier)ntruprimeOids.get(params);
    }

    static NTRULPRimeParameters ntrulprimeParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (NTRULPRimeParameters)ntruprimeParams.get(oid);
    }

    static ASN1ObjectIdentifier sntruprimeOidLookup(SNTRUPrimeParameters params)
    {
        return (ASN1ObjectIdentifier)sntruprimeOids.get(params);
    }

    static SNTRUPrimeParameters sntruprimeParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (SNTRUPrimeParameters)sntruprimeParams.get(oid);
    }

    static ASN1ObjectIdentifier mldsaOidLookup(MLDSAParameters params)
    {
        return (ASN1ObjectIdentifier)mldsaOids.get(params);
    }

    static MLDSAParameters mldsaParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (MLDSAParameters)mldsaParams.get(oid);
    }


    static ASN1ObjectIdentifier hqcOidLookup(HQCParameters params)
    {
        return (ASN1ObjectIdentifier)hqcOids.get(params);
    }

    static HQCParameters hqcParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (HQCParameters)hqcParams.get(oid);
    }
    
    static ASN1ObjectIdentifier mayoOidLookup(MayoParameters params)
    {
        return (ASN1ObjectIdentifier)mayoOids.get(params);
    }

    static MayoParameters mayoParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (MayoParameters)mayoParams.get(oid);
    }

    static ASN1ObjectIdentifier snovaOidLookup(SnovaParameters params)
    {
        return (ASN1ObjectIdentifier)snovaOids.get(params);
    }

    static SnovaParameters snovaParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (SnovaParameters)snovaParams.get(oid);
    }

    static NTRUPlusParameters ntruPlusParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (NTRUPlusParameters)ntruPlusParams.get(oid);
    }

    static ASN1ObjectIdentifier ntruPlusOidLookup(NTRUPlusParameters params)
    {
        return (ASN1ObjectIdentifier)ntruPlusOids.get(params);
    }

    private static boolean isRaw(byte[] data)
    {
        // check well-formed first
        ByteArrayInputStream bIn = new ByteArrayInputStream(data);

        int tag = bIn.read();
        int len = readLen(bIn);
        if (len != bIn.available())
        {
            return true;
        }

        return false;
    }

    static ASN1OctetString parseOctetData(byte[] data)
    {
        // check well-formed first
        if (!isRaw(data))
        {
            if (data[0] == BERTags.OCTET_STRING)
            {
                return ASN1OctetString.getInstance(data);
            }
        }

        return null;
    }

    static ASN1Primitive parseData(byte[] data)
    {
        // check well-formed first
        if (!isRaw(data))
        {
            if (data[0] == (BERTags.SEQUENCE | BERTags.CONSTRUCTED))
            {
                return ASN1Sequence.getInstance(data);
            }

            if (data[0] == BERTags.OCTET_STRING)
            {
                return ASN1OctetString.getInstance(data);
            }

            if ((data[0] & 0xff) == BERTags.TAGGED)
            {
                return ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(data), false);
            }
        }

        return null;
    }

    /**
     * ASN.1 length reader.
     */
    static int readLen(ByteArrayInputStream bIn)
    {
        int length = bIn.read();
        if (length < 0)
        {
            return -1;
        }
        if (length != (length & 0x7f))
        {
            int count = length & 0x7f;
            length = 0;
            while (count-- != 0)
            {
                length = (length << 8) + bIn.read();
            }
        }

        return length;
    }
}

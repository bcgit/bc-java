package org.bouncycastle.pqc.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.qtesla.QTESLASecurityCategory;
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

    static final Map picnicOids = new HashMap();
    static final Map picnicParams = new HashMap();

    static final Map frodoOids = new HashMap();
    static final Map frodoParams = new HashMap();

    static final Map saberOids = new HashMap();
    static final Map saberParams = new HashMap();

    static final Map mcElieceOids = new HashMap();
    static final Map mcElieceParams = new HashMap();

    static final Map sphincsPlusOids = new HashMap();
    static final Map sphincsPlusParams = new HashMap();

    static final Map sikeOids = new HashMap();
    static final Map sikeParams = new HashMap();

    static final Map ntruOids = new HashMap();
    static final Map ntruParams = new HashMap();

    static final Map falconOids = new HashMap();
    static final Map falconParams = new HashMap();

    static final Map kyberOids = new HashMap();
    static final Map kyberParams = new HashMap();

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

    static final Map rainbowOids = new HashMap();
    static final Map rainbowParams = new HashMap();

    static
    {
        categories.put(PQCObjectIdentifiers.qTESLA_p_I, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_I));
        categories.put(PQCObjectIdentifiers.qTESLA_p_III, Integers.valueOf(QTESLASecurityCategory.PROVABLY_SECURE_III));


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

        picnicOids.put(PicnicParameters.picnicl1fs, BCObjectIdentifiers.picnicl1fs);
        picnicOids.put(PicnicParameters.picnicl1ur, BCObjectIdentifiers.picnicl1ur);
        picnicOids.put(PicnicParameters.picnicl3fs, BCObjectIdentifiers.picnicl3fs);
        picnicOids.put(PicnicParameters.picnicl3ur, BCObjectIdentifiers.picnicl3ur);
        picnicOids.put(PicnicParameters.picnicl5fs, BCObjectIdentifiers.picnicl5fs);
        picnicOids.put(PicnicParameters.picnicl5ur, BCObjectIdentifiers.picnicl5ur);
        picnicOids.put(PicnicParameters.picnic3l1, BCObjectIdentifiers.picnic3l1);
        picnicOids.put(PicnicParameters.picnic3l3, BCObjectIdentifiers.picnic3l3);
        picnicOids.put(PicnicParameters.picnic3l5, BCObjectIdentifiers.picnic3l5);
        picnicOids.put(PicnicParameters.picnicl1full, BCObjectIdentifiers.picnicl1full);
        picnicOids.put(PicnicParameters.picnicl3full, BCObjectIdentifiers.picnicl3full);
        picnicOids.put(PicnicParameters.picnicl5full, BCObjectIdentifiers.picnicl5full);

        picnicParams.put(BCObjectIdentifiers.picnicl1fs, PicnicParameters.picnicl1fs);
        picnicParams.put(BCObjectIdentifiers.picnicl1ur, PicnicParameters.picnicl1ur);
        picnicParams.put(BCObjectIdentifiers.picnicl3fs, PicnicParameters.picnicl3fs);
        picnicParams.put(BCObjectIdentifiers.picnicl3ur, PicnicParameters.picnicl3ur);
        picnicParams.put(BCObjectIdentifiers.picnicl5fs, PicnicParameters.picnicl5fs);
        picnicParams.put(BCObjectIdentifiers.picnicl5ur, PicnicParameters.picnicl5ur);
        picnicParams.put(BCObjectIdentifiers.picnic3l1, PicnicParameters.picnic3l1);
        picnicParams.put(BCObjectIdentifiers.picnic3l3, PicnicParameters.picnic3l3);
        picnicParams.put(BCObjectIdentifiers.picnic3l5, PicnicParameters.picnic3l5);
        picnicParams.put(BCObjectIdentifiers.picnicl1full, PicnicParameters.picnicl1full);
        picnicParams.put(BCObjectIdentifiers.picnicl3full, PicnicParameters.picnicl3full);
        picnicParams.put(BCObjectIdentifiers.picnicl5full, PicnicParameters.picnicl5full);

        ntruOids.put(NTRUParameters.ntruhps2048509, BCObjectIdentifiers.ntruhps2048509);
        ntruOids.put(NTRUParameters.ntruhps2048677, BCObjectIdentifiers.ntruhps2048677);
        ntruOids.put(NTRUParameters.ntruhps4096821, BCObjectIdentifiers.ntruhps4096821);
        ntruOids.put(NTRUParameters.ntruhrss701, BCObjectIdentifiers.ntruhrss701);

        ntruParams.put(BCObjectIdentifiers.ntruhps2048509, NTRUParameters.ntruhps2048509);
        ntruParams.put(BCObjectIdentifiers.ntruhps2048677, NTRUParameters.ntruhps2048677);
        ntruParams.put(BCObjectIdentifiers.ntruhps4096821, NTRUParameters.ntruhps4096821);
        ntruParams.put(BCObjectIdentifiers.ntruhrss701, NTRUParameters.ntruhrss701);

        falconOids.put(FalconParameters.falcon_512, BCObjectIdentifiers.falcon_512);
        falconOids.put(FalconParameters.falcon_1024, BCObjectIdentifiers.falcon_1024);

        falconParams.put(BCObjectIdentifiers.falcon_512, FalconParameters.falcon_512);
        falconParams.put(BCObjectIdentifiers.falcon_1024, FalconParameters.falcon_1024);

        kyberOids.put(KyberParameters.kyber512, BCObjectIdentifiers.kyber512);
        kyberOids.put(KyberParameters.kyber768, BCObjectIdentifiers.kyber768);
        kyberOids.put(KyberParameters.kyber1024, BCObjectIdentifiers.kyber1024);

        kyberParams.put(BCObjectIdentifiers.kyber512, KyberParameters.kyber512);
        kyberParams.put(BCObjectIdentifiers.kyber768, KyberParameters.kyber768);
        kyberParams.put(BCObjectIdentifiers.kyber1024, KyberParameters.kyber1024);

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

        rainbowParams.put(BCObjectIdentifiers.rainbow_III_classic, RainbowParameters.rainbowIIIclassic);
        rainbowParams.put(BCObjectIdentifiers.rainbow_III_circumzenithal, RainbowParameters.rainbowIIIcircumzenithal);
        rainbowParams.put(BCObjectIdentifiers.rainbow_III_compressed, RainbowParameters.rainbowIIIcompressed);
        rainbowParams.put(BCObjectIdentifiers.rainbow_V_classic, RainbowParameters.rainbowVclassic);
        rainbowParams.put(BCObjectIdentifiers.rainbow_V_circumzenithal, RainbowParameters.rainbowVcircumzenithal);
        rainbowParams.put(BCObjectIdentifiers.rainbow_V_compressed, RainbowParameters.rainbowVcompressed);

        rainbowOids.put(RainbowParameters.rainbowIIIclassic, BCObjectIdentifiers.rainbow_III_classic);
        rainbowOids.put(RainbowParameters.rainbowIIIcircumzenithal, BCObjectIdentifiers.rainbow_III_circumzenithal);
        rainbowOids.put(RainbowParameters.rainbowIIIcompressed, BCObjectIdentifiers.rainbow_III_compressed);
        rainbowOids.put(RainbowParameters.rainbowVclassic, BCObjectIdentifiers.rainbow_V_classic);
        rainbowOids.put(RainbowParameters.rainbowVcircumzenithal, BCObjectIdentifiers.rainbow_V_circumzenithal);
        rainbowOids.put(RainbowParameters.rainbowVcompressed, BCObjectIdentifiers.rainbow_V_compressed);

        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_128s, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_128f, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_128s, BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_128f, BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_128s, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_128f, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_192s, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_192f, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_192s, BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_192f, BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_192s, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_192f, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_256s, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_256f, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_256s, BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_256f, BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_256s, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_256f, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);

        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_128s_simple, BCObjectIdentifiers.sphincsPlus_sha2_128s);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_128f_simple, BCObjectIdentifiers.sphincsPlus_sha2_128f);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_128s_simple, BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_128f_simple, BCObjectIdentifiers.sphincsPlus_shake_128f);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_128s_simple, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_128f_simple, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_192s_simple, BCObjectIdentifiers.sphincsPlus_sha2_192s);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_192f_simple, BCObjectIdentifiers.sphincsPlus_sha2_192f);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_192s_simple, BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_192f_simple, BCObjectIdentifiers.sphincsPlus_shake_192f);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_192s_simple, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_192f_simple, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_256s_simple, BCObjectIdentifiers.sphincsPlus_sha2_256s);
        sphincsPlusOids.put(SPHINCSPlusParameters.sha2_256f_simple, BCObjectIdentifiers.sphincsPlus_sha2_256f);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_256s_simple, BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.shake_256f_simple, BCObjectIdentifiers.sphincsPlus_shake_256f);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_256s_simple, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple);
        sphincsPlusOids.put(SPHINCSPlusParameters.haraka_256f_simple, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple);

        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_128s, SPHINCSPlusParameters.sha2_128s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_128f, SPHINCSPlusParameters.sha2_128f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_128f, SPHINCSPlusParameters.shake_128f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_192s, SPHINCSPlusParameters.sha2_192s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_192f, SPHINCSPlusParameters.sha2_192f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_192f, SPHINCSPlusParameters.shake_192f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_256s, SPHINCSPlusParameters.sha2_256s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_256f, SPHINCSPlusParameters.sha2_256f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_256f, SPHINCSPlusParameters.shake_256f_simple);

        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, SPHINCSPlusParameters.sha2_128s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, SPHINCSPlusParameters.sha2_128f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, SPHINCSPlusParameters.shake_128s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, SPHINCSPlusParameters.shake_128f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, SPHINCSPlusParameters.haraka_128s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, SPHINCSPlusParameters.haraka_128f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, SPHINCSPlusParameters.sha2_192s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, SPHINCSPlusParameters.sha2_192f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, SPHINCSPlusParameters.shake_192s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, SPHINCSPlusParameters.shake_192f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, SPHINCSPlusParameters.haraka_192s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, SPHINCSPlusParameters.haraka_192f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, SPHINCSPlusParameters.sha2_256s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, SPHINCSPlusParameters.sha2_256f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, SPHINCSPlusParameters.shake_256s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, SPHINCSPlusParameters.shake_256f);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, SPHINCSPlusParameters.haraka_256s);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, SPHINCSPlusParameters.haraka_256f);

        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, SPHINCSPlusParameters.sha2_128s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, SPHINCSPlusParameters.sha2_128f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, SPHINCSPlusParameters.shake_128s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, SPHINCSPlusParameters.shake_128f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, SPHINCSPlusParameters.haraka_128s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, SPHINCSPlusParameters.haraka_128f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, SPHINCSPlusParameters.sha2_192s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, SPHINCSPlusParameters.sha2_192f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, SPHINCSPlusParameters.shake_192s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, SPHINCSPlusParameters.shake_192f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, SPHINCSPlusParameters.haraka_192s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, SPHINCSPlusParameters.haraka_192f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, SPHINCSPlusParameters.sha2_256s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, SPHINCSPlusParameters.sha2_256f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, SPHINCSPlusParameters.shake_256s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, SPHINCSPlusParameters.shake_256f_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, SPHINCSPlusParameters.haraka_256s_simple);
        sphincsPlusParams.put(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, SPHINCSPlusParameters.haraka_256f_simple);
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

    static ASN1ObjectIdentifier sphincsPlusOidLookup(SPHINCSPlusParameters params)
    {
        return (ASN1ObjectIdentifier)sphincsPlusOids.get(params);
    }

    static SPHINCSPlusParameters sphincsPlusParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (SPHINCSPlusParameters)sphincsPlusParams.get(oid);
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

    static ASN1ObjectIdentifier picnicOidLookup(PicnicParameters params)
    {
        return (ASN1ObjectIdentifier)picnicOids.get(params);
    }

    static PicnicParameters picnicParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (PicnicParameters)picnicParams.get(oid);
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

    static ASN1ObjectIdentifier kyberOidLookup(KyberParameters params)
    {
        return (ASN1ObjectIdentifier)kyberOids.get(params);
    }

    static KyberParameters kyberParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (KyberParameters)kyberParams.get(oid);
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

    static ASN1ObjectIdentifier rainbowOidLookup(RainbowParameters params)
    {
        return (ASN1ObjectIdentifier)rainbowOids.get(params);
    }

    static RainbowParameters rainbowParamsLookup(ASN1ObjectIdentifier oid)
    {
        return (RainbowParameters)rainbowParams.get(oid);
    }
}

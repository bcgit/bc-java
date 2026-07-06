package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEParameters;
import org.bouncycastle.pqc.crypto.haetae.HAETAEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkParameters;
import org.bouncycastle.pqc.crypto.hawk.HawkPublicKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.HSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.HSSSigner;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mayo.MayoSigner;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusParameters;
import org.bouncycastle.pqc.crypto.ntruplus.NTRUPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVSigner;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaPublicKeyParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaSigner;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

/**
 * Hardening regression test (coverage findings #14 and #15): a malformed or
 * truncated PQC signature must make {@code verifySignature} return {@code false}
 * (never throw an unchecked exception), and a malformed-length PQC public-key
 * encoding must be rejected at construction. Both used to crash with
 * {@code ArrayIndexOutOfBoundsException} / {@code NegativeArraySizeException}.
 */
public class PqcMalformedInputTest
    extends TestCase
{
    private static final byte[] MESSAGE = new byte[]{ 0x01, 0x02, 0x03, 0x04 };

    // #15: verifySignature must return false (not throw) on an empty or one-byte signature.
    public void testMalformedSignatureReturnsFalse()
        throws Exception
    {
        // Falcon (variable-length signature, header + nonce guard).
        FalconParameters falconParams = FalconParameters.falcon_512;
        FalconSigner falcon = new FalconSigner();
        falcon.init(false, new FalconPublicKeyParameters(falconParams,
            new byte[14 * (1 << falconParams.getLogN()) / 8]));
        assertFalse(falcon.verifySignature(MESSAGE, new byte[0]));
        assertFalse(falcon.verifySignature(MESSAGE, new byte[1]));

        // MAYO (fixed-size signature).
        MayoParameters mayoParams = MayoParameters.mayo1;
        MayoSigner mayo = new MayoSigner();
        mayo.init(false, new MayoPublicKeyParameters(mayoParams, new byte[mayoParams.getCpkBytes()]));
        assertFalse(mayo.verifySignature(MESSAGE, new byte[0]));
        assertFalse(mayo.verifySignature(MESSAGE, new byte[1]));

        // SNOVA (fixed-size signature).
        SnovaParameters snovaParams = SnovaParameters.SNOVA_24_5_4_SSK;
        SnovaSigner snova = new SnovaSigner();
        snova.init(false, new SnovaPublicKeyParameters(snovaParams, new byte[snovaParams.getPublicKeyLength()]));
        assertFalse(snova.verifySignature(MESSAGE, new byte[0]));
        assertFalse(snova.verifySignature(MESSAGE, new byte[1]));

        // QR-UOV (signature || message envelope, must carry at least the signature).
        QRUOVParameters qruovParams = QRUOVParameters.qruov_1_q127_L3_v156_m54_shake;
        QRUOVSigner qruov = new QRUOVSigner();
        qruov.init(false, new QRUOVPublicKeyParameters(qruovParams, new byte[qruovParams.getPublicKeyBytes()]));
        assertFalse(qruov.verifySignature(MESSAGE, new byte[0]));
        assertFalse(qruov.verifySignature(MESSAGE, new byte[1]));

        // XMSS (stateful, parse must not throw out of verify).
        XMSSKeyPairGenerator xmssGen = new XMSSKeyPairGenerator();
        xmssGen.init(new XMSSKeyGenerationParameters(new XMSSParameters(4, new SHA256Digest()), new SecureRandom()));
        AsymmetricCipherKeyPair xmssKp = xmssGen.generateKeyPair();
        XMSSSigner xmss = new XMSSSigner();
        xmss.init(false, xmssKp.getPublic());
        assertFalse(xmss.verifySignature(MESSAGE, new byte[0]));
        assertFalse(xmss.verifySignature(MESSAGE, new byte[1]));

        // XMSS^MT (stateful).
        XMSSMTKeyPairGenerator xmssmtGen = new XMSSMTKeyPairGenerator();
        xmssmtGen.init(new XMSSMTKeyGenerationParameters(new XMSSMTParameters(6, 3, new SHA256Digest()), new SecureRandom()));
        AsymmetricCipherKeyPair xmssmtKp = xmssmtGen.generateKeyPair();
        XMSSMTSigner xmssmt = new XMSSMTSigner();
        xmssmt.init(false, xmssmtKp.getPublic());
        assertFalse(xmssmt.verifySignature(MESSAGE, new byte[0]));
        assertFalse(xmssmt.verifySignature(MESSAGE, new byte[1]));

        // LMS (stateful, variable structure decode).
        LMSKeyPairGenerator lmsGen = new LMSKeyPairGenerator();
        lmsGen.init(new LMSKeyGenerationParameters(
            new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), new SecureRandom()));
        AsymmetricCipherKeyPair lmsKp = lmsGen.generateKeyPair();
        LMSSigner lms = new LMSSigner();
        lms.init(false, lmsKp.getPublic());
        assertFalse(lms.verifySignature(MESSAGE, new byte[0]));
        assertFalse(lms.verifySignature(MESSAGE, new byte[1]));

        // HSS (stateful, variable structure decode).
        HSSKeyPairGenerator hssGen = new HSSKeyPairGenerator();
        hssGen.init(new HSSKeyGenerationParameters(
            new LMSParameters[]{ new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4) },
            new SecureRandom()));
        AsymmetricCipherKeyPair hssKp = hssGen.generateKeyPair();
        HSSSigner hss = new HSSSigner();
        hss.init(false, hssKp.getPublic());
        assertFalse(hss.verifySignature(MESSAGE, new byte[0]));
        assertFalse(hss.verifySignature(MESSAGE, new byte[1]));
    }

    // #14: a malformed-length public-key encoding must be rejected at construction.
    public void testMalformedPublicKeyRejected()
    {
        final byte[] tooShort = new byte[1];

        // Signature schemes.
        expectInvalidLength("ML-DSA (crypto.params)", new Runnable()
        {
            public void run()
            {
                new org.bouncycastle.crypto.params.MLDSAPublicKeyParameters(
                    org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_44, new byte[1]);
            }
        });
        expectInvalidLength("ML-DSA (pqc.crypto.mldsa)", new Runnable()
        {
            public void run()
            {
                new org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters(
                    org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters.ml_dsa_44, new byte[1]);
            }
        });
        expectInvalidLength("Falcon", new Runnable()
        {
            public void run()
            {
                new FalconPublicKeyParameters(FalconParameters.falcon_512, tooShort);
            }
        });
        expectInvalidLength("MAYO", new Runnable()
        {
            public void run()
            {
                new MayoPublicKeyParameters(MayoParameters.mayo1, tooShort);
            }
        });
        expectInvalidLength("SNOVA", new Runnable()
        {
            public void run()
            {
                new SnovaPublicKeyParameters(SnovaParameters.SNOVA_24_5_4_SSK, tooShort);
            }
        });
        expectInvalidLength("QR-UOV", new Runnable()
        {
            public void run()
            {
                new QRUOVPublicKeyParameters(QRUOVParameters.qruov_1_q127_L3_v156_m54_shake, tooShort);
            }
        });
        expectInvalidLength("Hawk", new Runnable()
        {
            public void run()
            {
                new HawkPublicKeyParameters(HawkParameters.Hawk_256, tooShort, 0, tooShort.length);
            }
        });
        expectInvalidLength("HAETAE", new Runnable()
        {
            public void run()
            {
                new HAETAEPublicKeyParameters(HAETAEParameters.haetae2, tooShort);
            }
        });
        expectInvalidLength("SQIsign", new Runnable()
        {
            public void run()
            {
                new SQIsignPublicKeyParameters(SQIsignParameters.sqisign_lvl1, tooShort);
            }
        });
        expectInvalidLength("SPHINCS-256", new Runnable()
        {
            public void run()
            {
                new SPHINCSPublicKeyParameters(tooShort);
            }
        });

        // KEM schemes.
        expectInvalidLength("Classic McEliece (legacy, non-standardised)", new Runnable()
        {
            public void run()
            {
                new CMCEPublicKeyParameters(CMCEParameters.mceliece348864r3, tooShort);
            }
        });
        expectInvalidLength("Classic McEliece (ISO 18033-2 standardised)", new Runnable()
        {
            public void run()
            {
                new org.bouncycastle.crypto.params.CMCEPublicKeyParameters(
                    org.bouncycastle.crypto.params.CMCEParameters.mceliece460896, tooShort);
            }
        });
        expectInvalidLength("Frodo (legacy, non-standardised)", new Runnable()
        {
            public void run()
            {
                new FrodoPublicKeyParameters(FrodoParameters.frodokem640aes, tooShort);
            }
        });
        expectInvalidLength("FrodoKEM (ISO 18033-2 standardised)", new Runnable()
        {
            public void run()
            {
                new FrodoKEMPublicKeyParameters(FrodoKEMParameters.frodokem976shake, tooShort);
            }
        });
        expectInvalidLength("HQC", new Runnable()
        {
            public void run()
            {
                new HQCPublicKeyParameters(HQCParameters.hqc128, tooShort);
            }
        });
        expectInvalidLength("NTRU", new Runnable()
        {
            public void run()
            {
                new NTRUPublicKeyParameters(NTRUParameters.ntruhps2048509, tooShort);
            }
        });
        expectInvalidLength("NTRU+", new Runnable()
        {
            public void run()
            {
                new NTRUPlusPublicKeyParameters(NTRUPlusParameters.ntruplus_kem_768, tooShort);
            }
        });
        expectInvalidLength("Streamlined NTRU Prime", new Runnable()
        {
            public void run()
            {
                new SNTRUPrimePublicKeyParameters(SNTRUPrimeParameters.sntrup653, tooShort);
            }
        });
        expectInvalidLength("NTRU LPRime", new Runnable()
        {
            public void run()
            {
                new NTRULPRimePublicKeyParameters(NTRULPRimeParameters.ntrulpr653, tooShort);
            }
        });
        expectInvalidLength("SABER", new Runnable()
        {
            public void run()
            {
                new SABERPublicKeyParameters(SABERParameters.lightsaberkem128r3, tooShort);
            }
        });
        expectInvalidLength("X-Wing", new Runnable()
        {
            public void run()
            {
                new XWingPublicKeyParameters(tooShort);
            }
        });
    }

    private void expectInvalidLength(String name, Runnable construct)
    {
        try
        {
            construct.run();
            fail(name + " accepted a malformed-length public key encoding");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }
}

package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.PQCParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.XMSSMTParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The NIST security category and classical security strength each post-quantum parameter set
 * reports, against NIST IR 8547 Tables 3 and 5.
 */
public class PQCParametersTest
    extends SimpleTest
{
    public String getName()
    {
        return "PQCParameters";
    }

    public void performTest()
        throws Exception
    {
        // ML-KEM (Table 5)
        check(MLKEMParameters.ml_kem_512, 1, 128);
        check(MLKEMParameters.ml_kem_768, 3, 192);
        check(MLKEMParameters.ml_kem_1024, 5, 256);

        // ML-DSA (Table 3)
        check(MLDSAParameters.ml_dsa_44, 2, 128);
        check(MLDSAParameters.ml_dsa_65, 3, 192);
        check(MLDSAParameters.ml_dsa_87, 5, 256);
        check(MLDSAParameters.ml_dsa_44_with_sha512, 2, 128);
        check(MLDSAParameters.ml_dsa_87_with_sha512, 5, 256);

        // SLH-DSA (Table 3)
        check(SLHDSAParameters.sha2_128s, 1, 128);
        check(SLHDSAParameters.sha2_128f, 1, 128);
        check(SLHDSAParameters.shake_128f, 1, 128);
        check(SLHDSAParameters.sha2_192s, 3, 192);
        check(SLHDSAParameters.shake_192f, 3, 192);
        check(SLHDSAParameters.sha2_256s, 5, 256);
        check(SLHDSAParameters.shake_256f, 5, 256);
        check(SLHDSAParameters.sha2_128s_with_sha256, 1, 128);
        check(SLHDSAParameters.shake_256s_with_shake256, 5, 256);

        // LMS (Table 3)
        check(LMSigParameters.lms_sha256_n32_h5, 5, 256);
        check(LMSigParameters.lms_sha256_n24_h10, 3, 192);
        check(LMSigParameters.lms_shake256_n32_h15, 5, 256);
        check(LMSigParameters.lms_shake256_n24_h20, 3, 192);
        check(LMOtsParameters.sha256_n32_w8, 5, 256);
        check(LMOtsParameters.sha256_n24_w4, 3, 192);
        check(LMOtsParameters.shake256_n32_w1, 5, 256);
        check(LMOtsParameters.shake256_n24_w2, 3, 192);
        check(org.bouncycastle.pqc.crypto.lms.LMSigParameters.lms_sha256_n32_h5, 5, 256);
        check(org.bouncycastle.pqc.crypto.lms.LMSigParameters.lms_shake256_n24_h10, 3, 192);
        check(org.bouncycastle.pqc.crypto.lms.LMOtsParameters.sha256_n32_w4, 5, 256);
        check(org.bouncycastle.pqc.crypto.lms.LMOtsParameters.shake256_n24_w8, 3, 192);

        // XMSS / XMSS^MT (Table 3; the SHA-512 set is outside SP 800-208 and capped at 256)
        check(new XMSSParameters(10, new SHA256Digest()), 5, 256);
        check(new XMSSParameters(10, new SHA512Digest()), 5, 256);
        check(new XMSSMTParameters(20, 2, new SHA256Digest()), 5, 256);
        check(XMSSParameters.lookupByOID(0x00000013), 3, 192);       // XMSS-SHAKE256_10_192
        check(XMSSMTParameters.lookupByOID(0x00000021), 3, 192);     // XMSSMT-SHA2_20/2_192
        // RFC 8391 SHAKE128 sets (n = 32): SHAKE128 caps the strength at 128 bits
        check(new XMSSParameters(10, new SHAKEDigest(128)), 1, 128);
        check(new XMSSMTParameters(20, 2, new SHAKEDigest(128)), 1, 128);
        check(new XMSSParameters(10, new SHAKEDigest(256)), 5, 256);

        // Falcon (round 3 submission) and HQC (October 2026 specification)
        check(FalconParameters.falcon_512, 1, 128);
        check(FalconParameters.falcon_1024, 5, 256);
        check(HQCParameters.hqc128, 1, 128);
        check(HQCParameters.hqc192, 3, 192);
        check(HQCParameters.hqc256, 5, 256);
    }

    private void check(PQCParameters params, int category, int classicalStrength)
    {
        isEquals(params + " category", category, params.getSecurityCategory());
        isEquals(params + " strength", classicalStrength, params.getClassicalSecurityStrength());
    }

    public static void main(String[] args)
    {
        runTest(new PQCParametersTest());
    }
}

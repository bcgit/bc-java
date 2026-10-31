package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.PQCParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.util.test.SimpleTest;

/**
 * NOTE: jdk1.4 overlay - identical to the base test minus the LMS and XMSS checks, as both
 * families are excluded from this build (see the lms/xmss excludes in ant/jdk14.xml).
 * <p>
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

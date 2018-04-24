package org.bouncycastle.jcajce.provider.test;

import java.security.AlgorithmParameters;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECAlgorithmParametersTest
    extends TestCase
{
    public static String[] entries = {
        "secp112r1",
        "1.3.132.0.6",
        "secp112r2",
        "1.3.132.0.7",
        "secp128r1",
        "1.3.132.0.28",
        "secp128r2",
        "1.3.132.0.29",
        "secp160k1",
        "1.3.132.0.9",
        "secp160r1",
        "1.3.132.0.8",
        "secp160r2",
        "1.3.132.0.30",
        "secp192k1",
        "1.3.132.0.31",
        "secp192r1",
        "NIST P-192",
        "X9.62 prime192v1",
        "1.2.840.10045.3.1.1",
        "secp224k1",
        "1.3.132.0.32",
        "secp224r1",
        "NIST P-224",
        "1.3.132.0.33",
        "secp256k1",
        "1.3.132.0.10",
        "secp256r1",
        "NIST P-256",
        "X9.62 prime256v1",
        "1.2.840.10045.3.1.7",
        "secp384r1",
        "NIST P-384",
        "1.3.132.0.34",
        "secp521r1",
        "NIST P-521",
        "1.3.132.0.35",
        "X9.62 prime192v2",
        "1.2.840.10045.3.1.2",
        "X9.62 prime192v3",
        "1.2.840.10045.3.1.3",
        "X9.62 prime239v1",
        "1.2.840.10045.3.1.4",
        "X9.62 prime239v2",
        "1.2.840.10045.3.1.5",
        "X9.62 prime239v3",
        "1.2.840.10045.3.1.6",
        "sect113r1",
        "1.3.132.0.4",
        "sect113r2",
        "1.3.132.0.5",
        "sect131r1",
        "1.3.132.0.22",
        "sect131r2",
        "1.3.132.0.23",
        "sect163k1",
        "NIST K-163",
        "1.3.132.0.1",
        "sect163r1",
        "1.3.132.0.2",
        "sect163r2",
        "NIST B-163",
        "1.3.132.0.15",
        "sect193r1",
        "1.3.132.0.24",
        "sect193r2",
        "1.3.132.0.25",
        "sect233k1",
        "NIST K-233",
        "1.3.132.0.26",
        "sect233r1",
        "NIST B-233",
        "1.3.132.0.27",
        "sect239k1",
        "1.3.132.0.3",
        "sect283k1",
        "NIST K-283",
        "1.3.132.0.16",
        "sect283r1",
        "NIST B-283",
        "1.3.132.0.17",
        "sect409k1",
        "NIST K-409",
        "1.3.132.0.36",
        "sect409r1",
        "NIST B-409",
        "1.3.132.0.37",
        "sect571k1",
        "NIST K-571",
        "1.3.132.0.38",
        "sect571r1",
        "NIST B-571",
        "1.3.132.0.39",
        "X9.62 c2tnb191v1",
        "1.2.840.10045.3.0.5",
        "X9.62 c2tnb191v2",
        "1.2.840.10045.3.0.6",
        "X9.62 c2tnb191v3",
        "1.2.840.10045.3.0.7",
        "X9.62 c2tnb239v1",
        "1.2.840.10045.3.0.11",
        "X9.62 c2tnb239v2",
        "1.2.840.10045.3.0.12",
        "X9.62 c2tnb239v3",
        "1.2.840.10045.3.0.13",
        "X9.62 c2tnb359v1",
        "1.2.840.10045.3.0.18",
        "X9.62 c2tnb431r1",
        "1.2.840.10045.3.0.20",
        "X9.62 c2pnb163v1",
        "1.2.840.10045.3.0.1",
        "X9.62 c2pnb163v2",
        "1.2.840.10045.3.0.2",
        "X9.62 c2pnb163v3",
        "1.2.840.10045.3.0.3",
        "X9.62 c2pnb176w1",
        "1.2.840.10045.3.0.4",
        "X9.62 c2pnb208w1",
        "1.2.840.10045.3.0.10",
        "X9.62 c2pnb272w1",
        "1.2.840.10045.3.0.16",
        "X9.62 c2pnb304w1",
        "1.2.840.10045.3.0.17",
        "X9.62 c2pnb368w1",
        "1.2.840.10045.3.0.19"};

    public void testRecogniseStandardCurveNames()
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        int testCount = 0;

        for (int i = 0; i != entries.length; i++)
        {
            AlgorithmParameters algParams = AlgorithmParameters.getInstance("EC", "BC");

            try
            {
                algParams.init(new ECGenParameterSpec(entries[i]));
            }
            catch (IllegalArgumentException e)
            {
                // ignore - this is due to a JDK 1.5 bug
                continue;
            }

            testCount++;
            ECParameterSpec ecSpec = null;

            ecSpec = algParams.getParameterSpec(ECParameterSpec.class);


            ECGenParameterSpec spec = algParams.getParameterSpec(ECGenParameterSpec.class);

            TestCase.assertEquals(nextOid(i), spec.getName());

            if (ecSpec != null)
            {
                AlgorithmParameters algParams2 = AlgorithmParameters.getInstance("EC", "BC");

                algParams2.init(new ECParameterSpec(ecSpec.getCurve(), ecSpec.getGenerator(), ecSpec.getOrder(), ecSpec.getCofactor()));

                spec = algParams2.getParameterSpec(ECGenParameterSpec.class);

                TestCase.assertEquals(nextOid(i), spec.getName());

                algParams.getEncoded();        // check that we can get an encoded spec.
            }
        }

        TestCase.assertTrue(testCount != 0); // at least one test must work!
    }

    private String nextOid(int index)
    {
        for (int i = index; i < entries.length; i++)
        {
            if (entries[i].charAt(0) >= '0' && entries[i].charAt(0) <= '2')
            {
                return entries[i];
            }
        }

        return null;
    }
}

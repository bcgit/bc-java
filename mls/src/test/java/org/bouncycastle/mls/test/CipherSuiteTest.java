package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertArrayEquals;

public class CipherSuiteTest
    extends TestCase
{
    public void testKDF() {
        int expandSize = 42;
        byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = Hex.decode("000102030405060708090a0b0c");
        byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");

        // Test with HKDF-SHA256
        CipherSuite suite256 = new CipherSuite(CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256);
        byte[] extracted256 = Hex.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] expanded256 = Hex.decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        assertArrayEquals(suite256.getKDF().extract(salt, ikm), extracted256);
        assertArrayEquals(suite256.getKDF().expand(extracted256, info, expandSize), expanded256);

        // Test with HKDF-SHA384
        CipherSuite suite384 = new CipherSuite(CipherSuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384);
        byte[] extracted384 = Hex.decode("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade");
        byte[] expanded384 = Hex.decode("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5");
        assertArrayEquals(suite384.getKDF().extract(salt, ikm), extracted384);
        assertArrayEquals(suite384.getKDF().expand(extracted384, info, expandSize), expanded384);

        // Test with HKDF-SHA384
        CipherSuite suite512 = new CipherSuite(CipherSuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521);
        byte[] extracted512 = Hex.decode("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237");
        byte[] expanded512 = Hex.decode("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb");
        assertArrayEquals(suite512.getKDF().extract(salt, ikm), extracted512);
        assertArrayEquals(suite512.getKDF().expand(extracted512, info, expandSize), expanded512);
    }

    public static TestSuite suite()
    {
        return new TestSuite(CipherSuiteTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}

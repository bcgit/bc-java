package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;

public class SecretTest
    extends TestCase
{
    public void testConsume() throws Exception {
        CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

        //     +--> b1 --> c1 --> d1
        //     |
        // a --+
        //     |
        //     +--> b2
        Secret a = new Secret(new byte[] { 1, 2, 3, 4});
        Secret b1 = a.deriveSecret(suite, "next1");
        Secret b2 = a.deriveSecret(suite, "next2");
        Secret c1 = b1.deriveSecret(suite, "next1");
        Secret d1 = c1.deriveSecret(suite, "next1");

        c1.consume();
        assertTrue(a.isConsumed());
        assertTrue(b1.isConsumed());
        assertTrue(c1.isConsumed());
        assertFalse(b2.isConsumed());
        assertFalse(d1.isConsumed());

        d1.consume();
        assertTrue(a.isConsumed());
        assertTrue(b1.isConsumed());
        assertTrue(c1.isConsumed());
        assertFalse(b2.isConsumed());
        assertTrue(d1.isConsumed());
    }

    public void testDerive() {
        // TODO test correctness of HkdfExpandLabel and DeriveSecret
    }

    public static TestSuite suite()
    {
        return new TestSuite(SecretTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}

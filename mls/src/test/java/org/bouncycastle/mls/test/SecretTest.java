package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;

public class SecretTest
    extends TestCase
{
    private final CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

    public void testConsume() throws Exception {
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

    public void testDerive() throws Exception {
        Secret base = new Secret(new byte[] {1, 2, 3, 4});

        // TODO test correctness of ExpandWithLabel

        Secret deriveSecretExpected = base.expandWithLabel(suite, "test", new byte[]{}, 32);
        Secret deriveSecretActual = base.deriveSecret(suite, "test");
        assertEquals(deriveSecretActual, deriveSecretExpected);

        Secret deriveTreeSecretExpected = base.expandWithLabel(suite, "test", new byte[]{5, 6, 7, 8}, 16);
        Secret deriveTreeSecretActual = base.deriveTreeSecret(suite, "test", 0x05060708, 16);
        assertEquals(deriveTreeSecretActual, deriveTreeSecretExpected);
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

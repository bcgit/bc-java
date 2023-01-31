package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.KeyGeneration;
import org.bouncycastle.mls.LeafIndex;
import org.bouncycastle.mls.GroupKeySet;
import org.bouncycastle.mls.TreeSize;
import org.bouncycastle.mls.crypto.CipherSuite;
import org.bouncycastle.mls.crypto.Secret;
import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidParameterException;

public class GroupKeySetTest
    extends TestCase
{
    private final CipherSuite suite = new CipherSuite(CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

    public void testRatchets() throws Exception {
        long generations = 10;
        TreeSize treeSize = TreeSize.forLeaves(8);
        int expectedKeySize = suite.getAEAD().getKeySize();
        int expectedNonceSize = suite.getAEAD().getNonceSize();

        byte[] encryptionSecretData = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Secret encryptionSecret = new Secret(encryptionSecretData);
        GroupKeySet keys = new GroupKeySet(suite, treeSize, encryptionSecret);

        // Verify next()
        for (long i = 0; i < treeSize.leafCount(); i++) {
            LeafIndex leaf = new LeafIndex(i);
            for (int generation = 0; generation < generations; generation++) {
                // TODO verify that the generated values are correct
                KeyGeneration hsGen = keys.handshakeRatchet(leaf).next();
                assertEquals(hsGen.generation, generation);
                assertEquals(hsGen.key.length, expectedKeySize);
                assertEquals(hsGen.nonce.length, expectedNonceSize);

                // TODO verify that the generated values are correct
                KeyGeneration appGen = keys.applicationRatchet(leaf).next();
                assertEquals(appGen.generation, generation);
                assertEquals(appGen.key.length, expectedKeySize);
                assertEquals(appGen.nonce.length, expectedNonceSize);
            }
        }

        // Verify get()
        LeafIndex leaf = new LeafIndex(0);
        KeyGeneration hsGen1 = keys.handshakeRatchet(leaf).next();
        int generation = hsGen1.generation;
        KeyGeneration hsGen2 = keys.handshakeRatchet(leaf).get(generation);
        assertEquals(hsGen1, hsGen2);

        // Verify erase()
        keys.handshakeRatchet(leaf).erase(generation);
        try {
            keys.handshakeRatchet(leaf).get(generation);
            fail("Ratchet failed to erase");
        } catch (InvalidParameterException e) {
            // Thrown as expected
        }
    }

    public static TestSuite suite()
    {
        return new TestSuite(GroupKeySetTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}

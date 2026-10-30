package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.mls.crypto.MlsCipherSuite;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * The post-quantum cipher suites of draft-ietf-mls-pq-ciphersuites: suite lookup, the KEM, hash and
 * signature algorithm of each, SignWithLabel / VerifyWithLabel and EncryptWithLabel / DecryptWithLabel
 * (RFC 9420 sec. 5.1.2 and 5.1.3). The group operations under these suites are covered by RemoveAddTest.
 */
public class PQCipherSuiteTest
    extends TestCase
{
    // suite id, HPKE KEM id, KDF hash length, HPKE enc size, signature public key size (0 = not fixed: ECDSA
    // and Ed25519 keys are checked by the classical tests), signature private key size
    private static final int[][] EXPECTED = {
        {MlsCipherSuite.MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519, HPKE.kem_X_WING, 32, 1120, 32, 32},
        {MlsCipherSuite.MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519, HPKE.kem_X_WING, 48, 1120, 32, 32},
        {MlsCipherSuite.MLS_128_MLKEM768P256_AES128GCM_SHA256_P256, HPKE.kem_MLKEM768_P256, 32, 1153, 65, 0},
        {MlsCipherSuite.MLS_128_MLKEM768P256_AES256GCM_SHA384_P256, HPKE.kem_MLKEM768_P256, 48, 1153, 65, 0},
        {MlsCipherSuite.MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384, HPKE.kem_MLKEM1024_P384, 48, 1665, 97, 0},
        {MlsCipherSuite.MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519, HPKE.kem_ML_KEM_768, 48, 1088, 32, 32},
        {MlsCipherSuite.MLS_128_MLKEM768_AES256GCM_SHA384_P256, HPKE.kem_ML_KEM_768, 48, 1088, 65, 0},
        {MlsCipherSuite.MLS_192_MLKEM1024_AES256GCM_SHA384_P384, HPKE.kem_ML_KEM_1024, 48, 1568, 97, 0},
        {MlsCipherSuite.MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44, HPKE.kem_X_WING, 48, 1120, 1312, 32},
        {MlsCipherSuite.MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65, HPKE.kem_ML_KEM_768, 48, 1088, 1952, 32},
        {MlsCipherSuite.MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87, HPKE.kem_ML_KEM_1024, 48, 1568, 2592, 32},
    };

    public void testSuiteTable()
        throws Exception
    {
        assertEquals(EXPECTED.length, MlsCipherSuite.PQ_SUITES.length);

        for (int i = 0; i != EXPECTED.length; i++)
        {
            short id = (short)EXPECTED[i][0];
            MlsCipherSuite suite = MlsCipherSuite.getSuite(id);
            String label = "suite 0x" + Integer.toHexString(id & 0xffff) + ": ";

            assertEquals(label + "id", id, suite.getSuiteID());
            assertEquals(label + "order", id, MlsCipherSuite.PQ_SUITES[i]);
            assertEquals(label + "hash length", EXPECTED[i][2], suite.getKDF().getHashLength());
            assertEquals(label + "enc size", EXPECTED[i][3], suite.getHPKE().getEncSize());

            // the placeholder ids are in the RFC 9420 private use range and not advertised by default
            assertTrue(label + "private use range", (id & 0xffff) >= 0xF000);
            assertFalse(label + "in ALL_SUPPORTED_SUITES", Arrays.contains(MlsCipherSuite.ALL_SUPPORTED_SUITES, id));
        }
    }

    public void testSignWithLabel()
        throws Exception
    {
        byte[] content = Strings.toByteArray("LeafNode content");

        for (int i = 0; i != EXPECTED.length; i++)
        {
            MlsCipherSuite suite = MlsCipherSuite.getSuite((short)EXPECTED[i][0]);
            String label = "suite 0x" + Integer.toHexString(suite.getSuiteID() & 0xffff) + ": ";

            AsymmetricCipherKeyPair kp = suite.generateSignatureKeyPair();
            byte[] pub = suite.serializeSignaturePublicKey(kp.getPublic());
            byte[] priv = suite.serializeSignaturePrivateKey(kp.getPrivate());

            if (EXPECTED[i][4] != 0)
            {
                assertEquals(label + "signature public key size", EXPECTED[i][4], pub.length);
            }
            if (EXPECTED[i][5] != 0)
            {
                assertEquals(label + "signature private key size", EXPECTED[i][5], priv.length);
            }

            // the private key serialization round trips to the same public key
            AsymmetricCipherKeyPair kp2 = suite.deserializeSignaturePrivateKey(priv);
            assertTrue(label + "private key round trip", Arrays.areEqual(pub, suite.serializeSignaturePublicKey(kp2.getPublic())));

            byte[] sig = suite.signWithLabel(priv, "LeafNodeTBS", content);

            assertTrue(label + "verify", suite.verifyWithLabel(pub, "LeafNodeTBS", content, sig));
            assertFalse(label + "verify wrong label", suite.verifyWithLabel(pub, "KeyPackageTBS", content, sig));
            assertFalse(label + "verify wrong content", suite.verifyWithLabel(pub, "LeafNodeTBS", Strings.toByteArray("other"), sig));

            byte[] badSig = Arrays.clone(sig);
            badSig[badSig.length / 2] ^= 1;
            assertFalse(label + "verify corrupt signature", suite.verifyWithLabel(pub, "LeafNodeTBS", content, badSig));
        }
    }

    public void testEncryptWithLabel()
        throws Exception
    {
        byte[] context = Strings.toByteArray("group context");
        byte[] plaintext = Strings.toByteArray("path secret");

        for (int i = 0; i != EXPECTED.length; i++)
        {
            MlsCipherSuite suite = MlsCipherSuite.getSuite((short)EXPECTED[i][0]);
            String label = "suite 0x" + Integer.toHexString(suite.getSuiteID() & 0xffff) + ": ";
            HPKE hpke = suite.getHPKE();

            // the HPKE key pair the TreeKEM nodes use, derived from a node secret of the suite's hash length
            byte[] nodeSecret = new byte[suite.getKDF().getHashLength()];
            nodeSecret[0] = (byte)i;
            AsymmetricCipherKeyPair kp = hpke.deriveKeyPair(nodeSecret);
            byte[] pub = hpke.serializePublicKey(kp.getPublic());
            byte[] priv = hpke.serializePrivateKey(kp.getPrivate());

            byte[][] sealed = suite.encryptWithLabel(pub, "UpdatePathNode", context, plaintext);
            byte[] ct = sealed[0];
            byte[] kemOutput = sealed[1];

            assertEquals(label + "kem output size", EXPECTED[i][3], kemOutput.length);
            assertTrue(label + "decrypt", Arrays.areEqual(plaintext, suite.decryptWithLabel(priv, "UpdatePathNode", context, kemOutput, ct)));

            try
            {
                suite.decryptWithLabel(priv, "Welcome", context, kemOutput, ct);
                fail(label + "decrypted under the wrong label");
            }
            catch (org.bouncycastle.crypto.InvalidCipherTextException e)
            {
                // expected
            }
        }
    }
}

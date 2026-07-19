package org.bouncycastle.openpgp.test;

import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for R-PGP-3: a truncated X25519/X448/ECDH encrypted session key must surface as a
 * {@link PGPException} from {@link BcPublicKeyDataDecryptorFactory#recoverSessionData}, not leak an
 * {@link ArrayIndexOutOfBoundsException} past the declared {@code throws PGPException}.
 * <p>
 * The PKESK parser ({@code PublicKeyEncSessionPacket}) imposes no minimum length on the encrypted
 * session key for ECDH/X25519/X448 ({@code data[0] = Streams.readAll(in)}), and the lightweight
 * decrypt path previously read {@code enc[pLen]} (X25519/X448) / {@code enc[0]},{@code enc[1]} (ECDH)
 * before its {@code checkRange} bounds check, so a short session key threw an uncaught AIOOBE. The JCE
 * sibling already wrapped the same reads in {@code catch (Exception)}; this test pins the restored parity.
 */
public class PGPShortEncSessionKeyTest
    extends SimpleTest
{
    public String getName()
    {
        return "PGPShortEncSessionKeyTest";
    }

    public void performTest()
        throws Exception
    {
        testShortX25519EncSessionKey();
        testShortX448EncSessionKey();
        testShortECDHEncSessionKey();
    }

    // X25519 / X448 dispatch through getSessionData, which read enc[pLen] before its length check.
    private void testShortX25519EncSessionKey()
        throws Exception
    {
        PGPKeyPair kp = new BcPGPKeyPairGeneratorProvider().get(PublicKeyPacket.VERSION_6, new Date())
            .generateX25519KeyPair();

        // encrypted session key shorter than the 32-byte X25519 ephemeral key.
        expectPGPException("X25519", kp.getPrivateKey(), PublicKeyAlgorithmTags.X25519, new byte[10]);
    }

    private void testShortX448EncSessionKey()
        throws Exception
    {
        PGPKeyPair kp = new BcPGPKeyPairGeneratorProvider().get(PublicKeyPacket.VERSION_6, new Date())
            .generateX448KeyPair();

        // encrypted session key shorter than the 56-byte X448 ephemeral key.
        expectPGPException("X448", kp.getPrivateKey(), PublicKeyAlgorithmTags.X448, new byte[10]);
    }

    // ECDH dispatches through recoverECDHSessionData, which read enc[0]/enc[1] before its length check.
    private void testShortECDHEncSessionKey()
        throws Exception
    {
        PGPKeyPair kp = new BcPGPKeyPairGeneratorProvider().get(PublicKeyPacket.VERSION_4, new Date())
            .generateNistP256ECDHKeyPair();

        // encrypted session key too short to hold the 2-byte point-length prefix.
        expectPGPException("ECDH", kp.getPrivateKey(), PublicKeyAlgorithmTags.ECDH, new byte[1]);
    }

    private void expectPGPException(String label, PGPPrivateKey privKey, int keyAlgorithm, byte[] shortEncKey)
        throws Exception
    {
        BcPublicKeyDataDecryptorFactory factory = new BcPublicKeyDataDecryptorFactory(privKey);
        try
        {
            factory.recoverSessionData(keyAlgorithm, new byte[][]{ shortEncKey }, PublicKeyEncSessionPacket.VERSION_3);
            fail("expected PGPException for short " + label + " encrypted session key");
        }
        catch (PGPException e)
        {
            // expected - a truncated session key is malformed input, not a runtime crash.
        }
    }

    public static void main(String[] args)
    {
        runTest(new PGPShortEncSessionKeyTest());
    }
}

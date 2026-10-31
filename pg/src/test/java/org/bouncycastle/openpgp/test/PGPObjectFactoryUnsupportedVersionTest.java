package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.MalformedPacketException;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * {@link PGPObjectFactory#nextObject()} declares only {@code IOException}, but a packet of an
 * unsupported version (or a secret key with an unknown S2K type) used to escape it as an unchecked
 * {@link UnsupportedPacketVersionException}. Each encoding below is a minimal packet reaching one of
 * the constructors that throws it.
 */
public class PGPObjectFactoryUnsupportedVersionTest
    extends SimpleTest
{
    // secret key packet, key version 116
    private static final String SECRET_KEY_BAD_VERSION = "c5057400000000";

    // public key packet, key version 116
    private static final String PUBLIC_KEY_BAD_VERSION = "c6057400000000";

    // one-pass signature packet, version 22
    private static final String OPS_BAD_VERSION = "c40116";

    // SKESK of unknown version (skipped), then an AEAD encrypted data packet of version 99
    private static final String AEAD_BAD_VERSION = "c30163d4026300";

    // SKESK of unknown version (skipped), then a signature packet of version 1 where the data packet should be
    private static final String SIG_AFTER_SESSION_KEYS = "c30163c20101";

    // v4 RSA secret key, s2k usage 254, AES-256, S2K type 0x75
    private static final String V4_SECRET_KEY_BAD_S2K = "c50f0400000000010008ff000203fe0975";

    public String getName()
    {
        return "PGPObjectFactoryUnsupportedVersionTest";
    }

    public void performTest()
        throws Exception
    {
        checkNextObject("secret key", SECRET_KEY_BAD_VERSION);
        checkNextObject("public key", PUBLIC_KEY_BAD_VERSION);
        checkNextObject("one-pass signature", OPS_BAD_VERSION);
        checkNextObject("AEAD encrypted data", AEAD_BAD_VERSION);
        checkNextObject("signature after session keys", SIG_AFTER_SESSION_KEYS);
        checkNextObject("v4 secret key S2K", V4_SECRET_KEY_BAD_S2K);

        // the v4 S2K read reports an unknown type as malformed at the packet level, as the v6 one does
        try
        {
            new BCPGInputStream(new ByteArrayInputStream(Hex.decode(V4_SECRET_KEY_BAD_S2K))).readPacket();
            fail("v4 secret key with unknown S2K type parsed");
        }
        catch (MalformedPacketException e)
        {
            isTrue(e.getCause() instanceof UnsupportedPacketVersionException);
        }
    }

    private void checkNextObject(String label, String hex)
    {
        byte[] encoding = Hex.decode(hex);

        checkNextObject(label, new BcPGPObjectFactory(encoding));
        checkNextObject(label, new JcaPGPObjectFactory(encoding));
    }

    private void checkNextObject(String label, PGPObjectFactory factory)
    {
        try
        {
            factory.nextObject();
            fail(label + ": nextObject() accepted the encoding");
        }
        catch (IOException e)
        {
            // expected: reported through the declared contract
        }
        catch (RuntimeException e)
        {
            fail(label + ": nextObject() threw unchecked " + e, e);
        }
    }

    public static void main(String[] args)
    {
        runTest(new PGPObjectFactoryUnsupportedVersionTest());
    }
}

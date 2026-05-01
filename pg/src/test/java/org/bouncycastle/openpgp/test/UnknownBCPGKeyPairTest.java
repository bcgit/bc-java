package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.UnknownBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.util.encoders.Hex;

public class UnknownBCPGKeyPairTest
        extends AbstractPgpKeyPairTest
{
    @Override
    public String getName()
    {
        return "UnknownBCPGKeyPairTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        testGetBitStrength();
    }

    private void testGetBitStrength()
            throws PGPException
    {
        byte[] raw = Hex.decode("decaffc0ffeebabe"); // 8 octets = 64-bit key size
        UnknownBCPGKey key = new UnknownBCPGKey(raw.length, raw);
        PublicKeyPacket packet = new PublicSubkeyPacket(
                PublicKeyPacket.VERSION_6,
                99, // unknown algorithm ID
                currentTimeRounded(),
                key);
        PGPPublicKey pgpKey = new PGPPublicKey(packet, new BcKeyFingerprintCalculator());
        isEquals("Unknown key getBitStrength() mismatch", 64, pgpKey.getBitStrength());
    }

    public static void main(String[] args)
    {
        runTest(new UnknownBCPGKeyPairTest());
    }
}

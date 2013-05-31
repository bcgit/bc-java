package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;

public interface KeyFingerPrintCalculator
{
    byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException;
}

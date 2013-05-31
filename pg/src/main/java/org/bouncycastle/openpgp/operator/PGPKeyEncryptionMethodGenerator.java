package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.openpgp.PGPException;

public abstract class PGPKeyEncryptionMethodGenerator
{
    public abstract ContainedPacket generate(int encAlgorithm, byte[] sessionInfo)
        throws PGPException;
}

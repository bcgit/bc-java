package org.bouncycastle.pqc.crypto.cross;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class CrossSigner
    implements MessageSigner
{
    @Override
    public void init(boolean forSigning, CipherParameters param)
    {

    }

    @Override
    public byte[] generateSignature(byte[] message)
    {
        return new byte[0];
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return false;
    }
}

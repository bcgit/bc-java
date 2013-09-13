package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;

public class GCFBBlockCipher
    implements BlockCipher
{
    public GCFBBlockCipher(BlockCipher engine)
    {

    }
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public String getAlgorithmName()
    {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public int getBlockSize()
    {
        return 0;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        return 0;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void reset()
    {
        //To change body of implemented methods use File | Settings | File Templates.
    }
}

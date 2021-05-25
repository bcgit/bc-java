package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;

final class BcTlsBlockCipherImpl
    implements TlsBlockCipherImpl
{
    private final boolean isEncrypting;
    private final BlockCipher cipher;

    private KeyParameter key;

    BcTlsBlockCipherImpl(BlockCipher cipher, boolean isEncrypting)
    {
        this.cipher = cipher;
        this.isEncrypting = isEncrypting;
    }

    public void setKey(byte[] key, int keyOff, int keyLen)
    {
        this.key = new KeyParameter(key, keyOff, keyLen);
    }

    public void init(byte[] iv, int ivOff, int ivLen)
    {
        cipher.init(isEncrypting, new ParametersWithIV(key, iv, ivOff, ivLen));
    }

    public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
    {
        int blockSize = cipher.getBlockSize();

        for (int i = 0; i < inputLength; i += blockSize)
        {
            cipher.processBlock(input, inputOffset + i, output, outputOffset + i);
        }

        return inputLength;
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }
}

package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

/**
 * an implementation of the RFC 3211 Key Wrap
 * Specification.
 */
public class RFC3211WrapEngine
    implements Wrapper
{
    private CBCBlockCipher   engine;
    private ParametersWithIV param;
    private boolean          forWrapping;
    private SecureRandom     rand;

    public RFC3211WrapEngine(BlockCipher engine)
    {
        this.engine = new CBCBlockCipher(engine);
    }

    public void init(
        boolean          forWrapping,
        CipherParameters param)
    {
        this.forWrapping = forWrapping;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom p = (ParametersWithRandom)param;

            rand = p.getRandom();

            if (!(p.getParameters() instanceof ParametersWithIV))
            {
                throw new IllegalArgumentException("RFC3211Wrap requires an IV");
            }

            this.param = (ParametersWithIV)p.getParameters();
        }
        else
        {
            if (forWrapping)
            {
                rand = CryptoServicesRegistrar.getSecureRandom();
            }

            if (!(param instanceof ParametersWithIV))
            {
                throw new IllegalArgumentException("RFC3211Wrap requires an IV");
            }

            this.param = (ParametersWithIV)param;
        }
    }

    public String getAlgorithmName()
    {
        return engine.getUnderlyingCipher().getAlgorithmName() + "/RFC3211Wrap";
    }

    public byte[] wrap(
        byte[]  in,
        int     inOff,
        int     inLen)
    {
        if (!forWrapping)
        {
            throw new IllegalStateException("not set for wrapping");
        }

        if (inLen > 255 || inLen < 0)
        {
            throw new IllegalArgumentException("input must be from 0 to 255 bytes");
        }
        
        engine.init(true, param);

        int blockSize = engine.getBlockSize();
        byte[] cekBlock;

        if (inLen + 4 < blockSize * 2)
        {
            cekBlock = new byte[blockSize * 2];
        }
        else
        {
            cekBlock = new byte[(inLen + 4) % blockSize == 0 ? inLen + 4 : ((inLen + 4) / blockSize + 1) * blockSize];
        }

        cekBlock[0] = (byte)inLen;

        System.arraycopy(in, inOff, cekBlock, 4, inLen);

        byte[] pad = new byte[cekBlock.length - (inLen + 4)];

        rand.nextBytes(pad);
        System.arraycopy(pad, 0, cekBlock, inLen + 4, pad.length);

        cekBlock[1] = (byte)~cekBlock[4];
        cekBlock[2] = (byte)~cekBlock[4 + 1];
        cekBlock[3] = (byte)~cekBlock[4 + 2];
        
        for (int i = 0; i < cekBlock.length; i += blockSize)
        {
            engine.processBlock(cekBlock, i, cekBlock, i);
        }

        for (int i = 0; i < cekBlock.length; i += blockSize)
        {
            engine.processBlock(cekBlock, i, cekBlock, i);
        }

        return cekBlock;
    }

    public byte[] unwrap(
        byte[]  in,
        int     inOff,
        int     inLen)
        throws InvalidCipherTextException
    {
        if (forWrapping)
        {
            throw new IllegalStateException("not set for unwrapping");
        }

        int blockSize = engine.getBlockSize();

        if (inLen < 2 * blockSize)
        {
            throw new InvalidCipherTextException("input too short");
        }
        
        byte[] cekBlock = new byte[inLen];
        byte[] iv = new byte[blockSize];

        System.arraycopy(in, inOff, cekBlock, 0, inLen);
        System.arraycopy(in, inOff, iv, 0, iv.length);
        
        engine.init(false, new ParametersWithIV(param.getParameters(), iv));

        for (int i = blockSize; i < cekBlock.length; i += blockSize)
        {
            engine.processBlock(cekBlock, i, cekBlock, i);    
        }

        System.arraycopy(cekBlock, cekBlock.length - iv.length, iv, 0, iv.length);

        engine.init(false, new ParametersWithIV(param.getParameters(), iv));

        engine.processBlock(cekBlock, 0, cekBlock, 0);

        engine.init(false, param);

        for (int i = 0; i < cekBlock.length; i += blockSize)
        {
            engine.processBlock(cekBlock, i, cekBlock, i);
        }

        boolean invalidLength = ((cekBlock[0] & 0xff) > cekBlock.length - 4);

        byte[] key;
        if (invalidLength)
        {
            key = new byte[cekBlock.length - 4];
        }
        else
        {
            key = new byte[cekBlock[0] & 0xff];
        }

        System.arraycopy(cekBlock, 4, key, 0, key.length);
        
        // Note: Using constant time comparison
        int nonEqual = 0;
        for (int i = 0; i != 3; i++)
        {
            byte check = (byte)~cekBlock[1 + i];
            nonEqual |= (check ^ cekBlock[4 + i]);
        }

        Arrays.clear(cekBlock);

        if (nonEqual != 0 | invalidLength)
        {
            throw new InvalidCipherTextException("wrapped key corrupted");
        }

        return key;
    }
}

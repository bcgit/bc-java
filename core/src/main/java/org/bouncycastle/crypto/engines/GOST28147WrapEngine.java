package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.util.Arrays;

public class GOST28147WrapEngine
    implements Wrapper
{
    private GOST28147Engine cipher = new GOST28147Engine();
    private GOST28147Mac mac = new GOST28147Mac();

    public void init(boolean forWrapping, CipherParameters param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom pr = (ParametersWithRandom)param;
            param = pr.getParameters();
        }
        
        ParametersWithUKM pU = (ParametersWithUKM)param;

        cipher.init(forWrapping, pU.getParameters());

        mac.init(new ParametersWithIV(pU.getParameters(), pU.getUKM()));
    }

    public String getAlgorithmName()
    {
        return "GOST28147Wrap";
    }

    public byte[] wrap(byte[] input, int inOff, int inLen)
    {
        mac.update(input, inOff, inLen);

        byte[] wrappedKey = new byte[inLen + mac.getMacSize()];

        cipher.processBlock(input, inOff, wrappedKey, 0);
        cipher.processBlock(input, inOff + 8, wrappedKey, 8);
        cipher.processBlock(input, inOff + 16, wrappedKey, 16);
        cipher.processBlock(input, inOff + 24, wrappedKey, 24);

        mac.doFinal(wrappedKey, inLen);

        return wrappedKey;
    }

    public byte[] unwrap(byte[] input, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        byte[] decKey = new byte[inLen - mac.getMacSize()];

        cipher.processBlock(input, inOff, decKey, 0);
        cipher.processBlock(input, inOff + 8, decKey, 8);
        cipher.processBlock(input, inOff + 16, decKey, 16);
        cipher.processBlock(input, inOff + 24, decKey, 24);

        byte[] macResult = new byte[mac.getMacSize()];

        mac.update(decKey, 0, decKey.length);

        mac.doFinal(macResult, 0);

        byte[] macExpected = new byte[mac.getMacSize()];

        System.arraycopy(input, inOff + inLen - 4, macExpected, 0, mac.getMacSize());

        if (!Arrays.constantTimeAreEqual(macResult, macExpected))
        {
            throw new IllegalStateException("mac mismatch");
        }

        return decKey;
    }
}

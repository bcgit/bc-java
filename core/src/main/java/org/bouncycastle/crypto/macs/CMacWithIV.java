package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * A non-NIST variant which allows passing of an IV to the underlying CBC cipher.
 * <p>Note: there isn't really a good reason to use an IV here, use the regular CMac where possible.</p>
 */
public class CMacWithIV
    extends CMac
{
    private BlockCipher cipher;

    public CMacWithIV(BlockCipher cipher)
    {
        super(cipher);
        this.cipher = cipher;
    }

    public CMacWithIV(BlockCipher cipher, int macSizeInBits)
    {
        super(cipher, macSizeInBits);
        this.cipher = cipher;
    }

    public void init(CipherParameters params)
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV pWithIV = (ParametersWithIV)params;

            super.init(pWithIV.getParameters());

            cipher.init(true, params);
        }
        else
        {
            super.init(params);
        }
    }
}

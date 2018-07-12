package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

/**
 * parameters for using an integrated cipher in stream mode.
 */
public class IESParameters
    implements CipherParameters
{
    private byte[]  derivation;
    private byte[]  encoding;
    private int     macKeySize;

    /**
     * @param derivation the derivation parameter for the KDF function.
     * @param encoding the encoding parameter for the KDF function.
     * @param macKeySize the size of the MAC key (in bits).
     */
    public IESParameters(
        byte[]  derivation,
        byte[]  encoding,
        int     macKeySize)
    {
        this.derivation = Arrays.clone(derivation);
        this.encoding = Arrays.clone(encoding);
        this.macKeySize = macKeySize;
    }

    public byte[] getDerivationV()
    {
        return Arrays.clone(derivation);
    }

    public byte[] getEncodingV()
    {
        return Arrays.clone(encoding);
    }

    public int getMacKeySize()
    {
        return macKeySize;
    }
}

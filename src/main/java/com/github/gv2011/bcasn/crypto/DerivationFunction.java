package com.github.gv2011.bcasn.crypto;

/**
 * base interface for general purpose byte derivation functions.
 */
public interface DerivationFunction
{
    public void init(DerivationParameters param);

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException;
}

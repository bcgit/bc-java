package com.github.gv2011.bcasn.crypto;

/**
 * With FIPS PUB 202 a new kind of message digest was announced which supported extendable output, or variable digest sizes.
 * This interface provides the extra method required to support variable output on an extended digest implementation.
 */
public interface Xof
    extends ExtendedDigest
{
    /**
     * Output the results of the final calculation for this digest to outLen number of bytes.
     *
     * @param out output array to write the output bytes to.
     * @param outOff offset to start writing the bytes at.
     * @param outLen the number of output bytes requested.
     * @return the number of bytes written
     */
    int doFinal(byte[] out, int outOff, int outLen);
}

package org.bouncycastle.crypto.signers;

import java.io.IOException;
import java.math.BigInteger;

/**
 * An interface for different encoding formats for DSA signatures.
 */
public interface DSAEncoding
{
    /**
     * Decode the (r, s) pair of a DSA signature.
     * 
     * @param n the order of the group that r, s belong to.
     * @param encoding an encoding of the (r, s) pair of a DSA signature.
     * @return the (r, s) of a DSA signature, stored in an array of exactly two elements, r followed by s.
     * @throws IOException
     */
    BigInteger[] decode(BigInteger n, byte[] encoding) throws IOException;

    /**
     * Encode the (r, s) pair of a DSA signature.
     * 
     * @param n the order of the group that r, s belong to.
     * @param r the r value of a DSA signature.
     * @param s the s value of a DSA signature.
     * @return an encoding of the DSA signature given by the provided (r, s) pair.
     * @throws IOException
     */
    byte[] encode(BigInteger n, BigInteger r, BigInteger s) throws IOException;
}

package org.bouncycastle.crypto.hash2curve.impl;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.Arrays;

/**
 * XmdMessageExpansion is an implementation of the MessageExpansion interface, used to expand a
 * given message to a specified length in bytes while following cryptographic domain separation
 * principles. The implementation uses a selected hash function to achieve the expansion.
 */
public class XmdMessageExpansion implements MessageExpansion
{
    /** The Digest function for this instance */
    private final Digest digest;

    /** The input block size of the selected hash algorithm */
    private final int s;

    /** The size in bytes of hash outputs */
    private final int hashOutputBytes;

    /**
     * Constructs an XmdMessageExpansion instance capable of performing cryptographic message expansion
     * using the specified digest algorithm, security parameter, and custom input block size parameter.
     * The security of the curve's operations is validated against the output size of the digest
     * algorithm.
     *
     * @param digest the cryptographic digest algorithm to be used
     * @param k the security parameter defining the required minimum security strength, in bits
     * @param s the input block size parameter for the cryptographic digest algorithm
     * @throws IllegalArgumentException if the hash output size is too small for the specified security
     * level
     */
    public XmdMessageExpansion(final Digest digest, final int k, final int s)
    {
        this.digest = digest;
        this.s = s;
        this.hashOutputBytes = digest.getDigestSize();
        if (this.hashOutputBytes < (int)Math.ceil((double)(k * 2) / 8))
        {
            throw new IllegalArgumentException("Hash output size is too small for the security level of the curve");
        }
    }

    /**
     * Constructs an XmdMessageExpansion instance with the given digest algorithm and security
     * parameter.
     *
     * @param digest the cryptographic digest algorithm to be used
     * @param k the security parameter defining the required minimum security strength
     */
    public XmdMessageExpansion(final ExtendedDigest digest, final int k)
    {
        this(digest, k, getInputBlockSize(digest));
    }

    /**
     * Determines the input block size for a given cryptographic digest algorithm.
     *
     * @param digest the cryptographic digest algorithm whose input block size is to be determined
     * @return the input block size in bits for the provided digest algorithm
     * @throws IllegalArgumentException if the provided digest algorithm is not supported or has an
     * illegal configuration
     */
    private static int getInputBlockSize(final ExtendedDigest digest)
    {
        return digest.getByteLength() * 8;
    }

    /**
     * Expands a given input message to a fixed-length output, using a cryptographic digest and
     * additional parameters such as domain separation tag (DST) and desired output length. This method
     * is compliant with hash-to-curve message expansion defined in certain cryptographic algorithms and
     * standards.
     *
     * @param msg the input message to be expanded
     * @param dst the domain separation tag used to isolate cryptographic domains
     * @param lenInBytes the desired byte-length of the output message
     * @return the byte array resulting from the message expansion process
     * @throws IllegalArgumentException if ell exceeds 255, lenInBytes exceeds 65535, or dst length is
     * greater than 255
     */
    public byte[] expandMessage(final byte[] msg, final byte[] dst, final int lenInBytes)
    {
        final int ell = (int)Math.ceil((double)lenInBytes / this.hashOutputBytes);
        if (ell > 255)
        {
            throw new IllegalArgumentException("Ell parameter must not be greater than 255. Current value = " + ell);
        }
        if (lenInBytes > 65535)
        {
            throw new IllegalArgumentException(
                "Output size must not be greater than 65535. Current value = " + lenInBytes);
        }
        if (dst.length > 255)
        {
            throw new IllegalArgumentException("DST size must not be greater than 255. Current value = " + dst.length);
        }
        final byte[] dstPrime = Arrays.concatenate(dst, H2cUtils.i2osp(dst.length, 1));
        final byte[] zPad = H2cUtils.i2osp(0, this.s / 8);
        final byte[] libStr = H2cUtils.i2osp(lenInBytes, 2);
        final byte[] msgPrime = Arrays.concatenate(new byte[][]
        { zPad, msg, libStr, H2cUtils.i2osp(0, 1), dstPrime });
        final byte[][] b = new byte[ell + 1][this.hashOutputBytes];
        b[0] = this.hash(msgPrime);
        b[1] = this.hash(Arrays.concatenate(b[0], H2cUtils.i2osp(1, 1), dstPrime));
        byte[] uniformBytes = Arrays.clone(b[1]);
        for (int i = 2; i <= ell; i++)
        {
            b[i] = this.hash(Arrays.concatenate(H2cUtils.xor(b[0], b[i - 1]), H2cUtils.i2osp(i, 1), dstPrime));
            uniformBytes = Arrays.concatenate(uniformBytes, b[i]);
        }
        return Arrays.copyOfRange(uniformBytes, 0, lenInBytes);
    }

    /**
     * Calculates a hash over a message
     *
     * @param message message
     * @return hash value
     */
    private byte[] hash(final byte[] message)
    {
        final Digest digestInstance = DigestFactory.cloneDigest(this.digest);
        digestInstance.update(message, 0, message.length);
        final byte[] hashResult = new byte[this.digest.getDigestSize()];
        digestInstance.doFinal(hashResult, 0);
        return hashResult;
    }
}

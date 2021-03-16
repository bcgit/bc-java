package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * ParallelHash - a hash designed  to  support the efficient hashing of very long strings, by taking advantage
 * of the parallelism available in modern processors with an optional XOF mode.
 * <p>
 * From NIST Special Publication 800-185 - SHA-3 Derived Functions:cSHAKE, KMAC, TupleHash and ParallelHash
 * </p>
 */
public class ParallelHash
    implements Xof, Digest
{
    private static final byte[] N_PARALLEL_HASH = Strings.toByteArray("ParallelHash");

    private final CSHAKEDigest cshake;
    private final CSHAKEDigest compressor;
    private final int bitLength;
    private final int outputLength;
    private final int B;
    private final byte[] buffer;
    private final byte[] compressorBuffer;

    private boolean firstOutput;
    private int nCount;
    private int bufOff;

    /**
     * Base constructor.
     *
     * @param bitLength bit length of the underlying SHAKE function, 128 or 256.
     * @param S the customization string - available for local use.
     * @param B the blocksize (in bytes) for hashing.
     */
    public ParallelHash(int bitLength, byte[] S, int B)
    {
        this(bitLength, S, B, bitLength * 2);
    }

    public ParallelHash(int bitLength, byte[] S, int B, int outputSize)
    {
        this.cshake = new CSHAKEDigest(bitLength, N_PARALLEL_HASH, S);
        this.compressor = new CSHAKEDigest(bitLength, new byte[0], new byte[0]);
        this.bitLength = bitLength;
        this.B = B;
        this.outputLength = (outputSize + 7) / 8;
        this.buffer = new byte[B];
        this.compressorBuffer = new byte[bitLength * 2 / 8];

        reset();
    }

    public ParallelHash(ParallelHash source)
    {
        this.cshake = new CSHAKEDigest(source.cshake);
        this.compressor = new CSHAKEDigest(source.compressor);
        this.bitLength = source.bitLength;
        this.B = source.B;
        this.outputLength = source.outputLength;
        this.buffer = Arrays.clone(source.buffer);
        this.compressorBuffer = Arrays.clone(source.compressorBuffer);
    }

    public String getAlgorithmName()
    {
        return "ParallelHash" + cshake.getAlgorithmName().substring(6);
    }

    public int getByteLength()
    {
        return cshake.getByteLength();
    }

    public int getDigestSize()
    {
        return outputLength;
    }

    public void update(byte in)
        throws IllegalStateException
    {
        buffer[bufOff++] = in;
        if (bufOff == buffer.length)
        {
            compress();
        }
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        len = Math.max(0,  len);

        //
        // fill the current word
        //
        int i = 0;
        if (bufOff != 0)
        {
            while (i < len && bufOff != buffer.length)
            {
                buffer[bufOff++] = in[inOff + i++];
            }

            if (bufOff == buffer.length)
            {
                compress();
            }
        }

        if (i < len)
        {
            while (len - i > B)
            {
                compress(in, inOff + i, B);
                i += B;
            }
        }

        while (i < len)
        {
            update(in[inOff + i++]);
        }
    }

    private void compress()
    {
        compress(buffer, 0, bufOff);
        bufOff = 0;
    }

    private void compress(byte[] buf, int offSet, int len)
    {
        compressor.update(buf, offSet, len);
        compressor.doFinal(compressorBuffer, 0, compressorBuffer.length);

        cshake.update(compressorBuffer, 0, compressorBuffer.length);

        nCount++;
    }

    private void wrapUp(int outputSize)
    {
        if (bufOff != 0)
        {
            compress();
        }
        byte[] nOut = XofUtils.rightEncode(nCount);
        byte[] encOut = XofUtils.rightEncode(outputSize * 8);

        cshake.update(nOut, 0, nOut.length);
        cshake.update(encOut, 0, encOut.length);

        firstOutput = false;
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (firstOutput)
        {
            wrapUp(outputLength);
        }

        int rv = cshake.doFinal(out, outOff, getDigestSize());

        reset();

        return rv;
    }

    public int doFinal(byte[] out, int outOff, int outLen)
    {
        if (firstOutput)
        {
            wrapUp(outputLength);
        }
        
        int rv = cshake.doFinal(out, outOff, outLen);

        reset();

        return rv;
    }

    public int doOutput(byte[] out, int outOff, int outLen)
    {
        if (firstOutput)
        {
            wrapUp(0);
        }

        return cshake.doOutput(out, outOff, outLen);
    }

    public void reset()
    {
        cshake.reset();
        Arrays.clear(buffer);

        byte[] hdr = XofUtils.leftEncode(B);
        cshake.update(hdr, 0, hdr.length);

        nCount = 0;
        bufOff = 0;
        firstOutput = true;
    }
}

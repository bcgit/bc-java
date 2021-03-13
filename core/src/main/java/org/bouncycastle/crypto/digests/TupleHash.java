package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Strings;

/**
 * TupleHash - a hash designed  to  simply  hash  a  tuple  of  input  strings,  any  or  all  of  which  may  be  empty  strings,
 *  in  an  unambiguous way with an optional XOF mode.
 * <p>
 * From NIST Special Publication 800-185 - SHA-3 Derived Functions:cSHAKE, KMAC, TupleHash and ParallelHash
 * </p>
 */
public class TupleHash
    implements Xof, Digest
{
    private static final byte[] N_TUPLE_HASH = Strings.toByteArray("TupleHash");

    private final CSHAKEDigest cshake;
    private final int bitLength;
    private final int outputLength;

    private boolean firstOutput;

    /**
     * Base constructor.
     *
     * @param bitLength bit length of the underlying SHAKE function, 128 or 256.
     * @param S         the customization string - available for local use.
     */
    public TupleHash(int bitLength, byte[] S)
    {
        this(bitLength, S, bitLength * 2);
    }

    public TupleHash(int bitLength, byte[] S, int outputSize)
    {
        this.cshake = new CSHAKEDigest(bitLength, N_TUPLE_HASH, S);
        this.bitLength = bitLength;
        this.outputLength = (outputSize + 7) / 8;

        reset();
    }

    public TupleHash(TupleHash original)
    {
        this.cshake = new CSHAKEDigest(original.cshake);
        this.bitLength = cshake.fixedOutputLength;
        this.outputLength = bitLength * 2 / 8;
        this.firstOutput = original.firstOutput;
    }

    public String getAlgorithmName()
    {
        return "TupleHash" + cshake.getAlgorithmName().substring(6);
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
        byte[] bytes = XofUtils.encode(in);
        cshake.update(bytes, 0, bytes.length);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        byte[] bytes = XofUtils.encode(in, inOff, len);
        cshake.update(bytes, 0, bytes.length);
    }

    private void wrapUp(int outputSize)
    {
        byte[] encOut = XofUtils.rightEncode(outputSize * 8L);

        cshake.update(encOut, 0, encOut.length);

        firstOutput = false;
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (firstOutput)
        {
            wrapUp(getDigestSize());
        }
        
        int rv = cshake.doFinal(out, outOff, getDigestSize());

        reset();

        return rv;
    }

    public int doFinal(byte[] out, int outOff, int outLen)
    {
        if (firstOutput)
        {
            wrapUp(getDigestSize());
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
        firstOutput = true;
    }
}

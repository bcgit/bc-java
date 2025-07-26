package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.SavableDigest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

/**
 * TupleHash - a hash designed  to  simply  hash  a  tuple  of  input  strings,  any  or  all  of  which  may  be  empty  strings,
 *  in  an  unambiguous way with an optional XOF mode.
 * <p>
 * From NIST Special Publication 800-185 - SHA-3 Derived Functions:cSHAKE, KMAC, TupleHash and ParallelHash
 * </p>
 */
public class TupleHash
    implements Xof, SavableDigest
{
    private static final byte[] N_TUPLE_HASH = Strings.toByteArray("TupleHash");

    private final CSHAKEDigest cshake;

    private int bitLength;
    private int outputLength;
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
        this.bitLength = original.bitLength;
        this.outputLength = original.outputLength;
        this.firstOutput = original.firstOutput;
    }

    public TupleHash(byte[] state)
    {
        this.cshake = new CSHAKEDigest(Arrays.copyOfRange(state, 0, state.length - 9));
        this.bitLength = Pack.bigEndianToInt(state, state.length - 9);
        this.outputLength = Pack.bigEndianToInt(state, state.length - 5);
        this.firstOutput = state[state.length - 1] != 0;
    }

    private void copyIn(TupleHash original)
    {
        this.cshake.reset(original.cshake);
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

    public byte[] getEncodedState()
    {
        byte[] cshakeState = this.cshake.getEncodedState();
        byte[] extraState = new byte[4 + 4 + 1];

        Pack.intToBigEndian(this.bitLength, extraState, 0);
        Pack.intToBigEndian(this.outputLength, extraState, 4);
        extraState[8] = this.firstOutput ? (byte)1 : (byte)0;

        return Arrays.concatenate(cshakeState, extraState);
    }

    public Memoable copy()
    {
        return new TupleHash(this);
    }

    public void reset(Memoable other)
    {
        copyIn((TupleHash)other);
    }
}

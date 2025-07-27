package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.EncodableDigest;
import org.bouncycastle.crypto.digests.XofUtils;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

/**
 * KMAC - MAC with optional XOF mode.
 * <p>
 * From NIST Special Publication 800-185 - SHA-3 Derived Functions:cSHAKE, KMAC, TupleHash and ParallelHash
 * </p>
 */
public class KMAC
    implements Mac, Xof, Memoable, EncodableDigest
{
    private static final byte[] padding = new byte[100];

    private final CSHAKEDigest cshake;
    
    private int bitLength;
    private int outputLength;

    private byte[] key;
    private boolean initialised;
    private boolean firstOutput;

    /**
     * Base constructor.
     *
     * @param bitLength bit length of the underlying SHAKE function, 128 or 256.
     * @param S         the customization string - available for local use.
     */
    public KMAC(int bitLength, byte[] S)
    {
        this.cshake = new CSHAKEDigest(bitLength, Strings.toByteArray("KMAC"), S);
        this.bitLength = bitLength;
        this.outputLength = bitLength * 2 / 8;
    }

    public KMAC(KMAC original)
    {
        this.cshake = new CSHAKEDigest(original.cshake);
        this.bitLength = original.bitLength;
        this.outputLength = original.outputLength;
        this.key = original.key;
        this.initialised = original.initialised;
        this.firstOutput = original.firstOutput;
    }

    public KMAC(byte[] state)
    {
        this.key = new byte[state[0] & 0xff];
        System.arraycopy(state, 1, key, 0, key.length);
        this.cshake = new CSHAKEDigest(Arrays.copyOfRange(state, 1 + key.length, state.length - 10));
                
        this.bitLength = Pack.bigEndianToInt(state, state.length - 10);
        this.outputLength = Pack.bigEndianToInt(state, state.length - 6);
        this.initialised = state[state.length - 2] != 0;
        this.firstOutput = state[state.length - 1] != 0;
    }

    private void copyIn(KMAC original)
    {
        this.cshake.reset(original.cshake);
        this.bitLength = original.bitLength;
        this.outputLength = original.outputLength;
        this.initialised = original.initialised;
        this.firstOutput = original.firstOutput;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        KeyParameter kParam = (KeyParameter)params;

        this.key = Arrays.clone(kParam.getKey());
        if (this.key.length > 255)  // 2^2040
        {
            throw new IllegalArgumentException("key length must be between 0 and 2040 bits");
        }

        this.initialised = true;

        reset();
    }

    public String getAlgorithmName()
    {
        return "KMAC" + cshake.getAlgorithmName().substring(6);
    }

    public int getByteLength()
    {
        return cshake.getByteLength();
    }

    public int getMacSize()
    {
        return outputLength;
    }

    public int getDigestSize()
    {
        return outputLength;
    }

    public void update(byte in)
        throws IllegalStateException
    {
        if (!initialised)
        {
            throw new IllegalStateException("KMAC not initialized");
        }

        cshake.update(in);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        if (!initialised)
        {
            throw new IllegalStateException("KMAC not initialized");
        }

        cshake.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        if (firstOutput)
        {
            if (!initialised)
            {
                throw new IllegalStateException("KMAC not initialized");
            }

            byte[] encOut = XofUtils.rightEncode(getMacSize() * 8);

            cshake.update(encOut, 0, encOut.length);
        }
        
        int rv = cshake.doFinal(out, outOff, getMacSize());

        reset();

        return rv;
    }

    public int doFinal(byte[] out, int outOff, int outLen)
    {
        if (firstOutput)
        {
            if (!initialised)
            {
                throw new IllegalStateException("KMAC not initialized");
            }

            byte[] encOut = XofUtils.rightEncode(outLen * 8);

            cshake.update(encOut, 0, encOut.length);
        }
        
        int rv = cshake.doFinal(out, outOff, outLen);

        reset();

        return rv;
    }

    public int doOutput(byte[] out, int outOff, int outLen)
    {
        if (firstOutput)
        {
            if (!initialised)
            {
                throw new IllegalStateException("KMAC not initialized");
            }

            byte[] encOut = XofUtils.rightEncode(0);

            cshake.update(encOut, 0, encOut.length);

            firstOutput = false;
        }

        return cshake.doOutput(out, outOff, outLen);
    }

    public void reset()
    {
        cshake.reset();

        if (key != null)
        {
            if (bitLength == 128)
            {
                bytePad(key, 168);
            }
            else
            {
                bytePad(key, 136);
            }
        }

        firstOutput = true;
    }

    private void bytePad(byte[] X, int w)
    {
        byte[] bytes = XofUtils.leftEncode(w);
        update(bytes, 0, bytes.length);
        byte[] encX = encode(X);
        update(encX, 0, encX.length);

        int required = w - ((bytes.length + encX.length) % w);

        if (required > 0 && required != w)
        {
            while (required > padding.length)
            {
                update(padding, 0, padding.length);
                required -= padding.length;
            }

            update(padding, 0, required);
        }
    }

    private static byte[] encode(byte[] X)
    {
        return Arrays.concatenate(XofUtils.leftEncode(X.length * 8), X);
    }

    public byte[] getEncodedState()
    {
        if (!this.initialised)
        {
            throw new IllegalStateException("KMAC not initialised");
        }

        byte[] cshakeState = this.cshake.getEncodedState();
        byte[] extraState = new byte[4 + 4 + 2];

        Pack.intToBigEndian(this.bitLength, extraState, 0);
        Pack.intToBigEndian(this.outputLength, extraState, 4);
        extraState[8] = this.initialised ? (byte)1 : (byte)0;
        extraState[9] = this.firstOutput ? (byte)1 : (byte)0;

        byte[] enc = new byte[1 + key.length + cshakeState.length + extraState.length];

        enc[0] = (byte)key.length; // key capped at 255 bytes.
        System.arraycopy(key, 0, enc, 1, key.length);
        System.arraycopy(cshakeState, 0, enc, 1 + key.length, cshakeState.length);
        System.arraycopy(extraState, 0, enc, 1 + key.length + cshakeState.length, extraState.length);

        return enc;
    }

    public Memoable copy()
    {
        return new KMAC(this);
    }

    public void reset(Memoable other)
    {
        copyIn((KMAC)other);
    }
}

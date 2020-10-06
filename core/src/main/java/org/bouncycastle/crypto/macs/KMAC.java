package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.XofUtils;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * KMAC - MAC with optional XOF mode.
 * <p>
 * From NIST Special Publication 800-185 - SHA-3 Derived Functions:cSHAKE, KMAC, TupleHash and ParallelHash
 * </p>
 */
public class KMAC
    implements Mac, Xof
{
    private static final byte[] padding = new byte[100];

    private final CSHAKEDigest cshake;
    private final int bitLength;
    private final int outputLength;

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

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        KeyParameter kParam = (KeyParameter)params;

        this.key = Arrays.clone(kParam.getKey());
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
}

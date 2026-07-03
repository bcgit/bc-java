package org.bouncycastle.jcajce.provider.digest;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.MacSpi;

import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.jcajce.spec.KMACParameterSpec;

/**
 * MacSpi for KMAC128 / KMAC256 (NIST SP 800-185), supporting the RFC 8702
 * KMACwithSHAKEnnn-params customization-string and output-length controls
 * through {@link KMACParameterSpec}.
 * <p>
 * Without parameters, the MAC defaults to a {@code 2 * bitLength} bit output
 * and an empty customization string &mdash; the standard SP 800-185 settings.
 */
abstract class KMacSpi
    extends MacSpi
{
    private final int bitLength;
    private final int defaultOutputBytes;

    private KMAC macEngine;
    private int outputBytes;

    KMacSpi(int bitLength)
    {
        this.bitLength = bitLength;
        this.defaultOutputBytes = (bitLength * 2) / 8;
        this.macEngine = new KMAC(bitLength, new byte[0]);
        this.outputBytes = defaultOutputBytes;
    }

    protected void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (key == null)
        {
            throw new InvalidKeyException("key is null");
        }

        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null)
        {
            throw new InvalidKeyException("key has no encoding");
        }

        if (params == null)
        {
            this.macEngine = new KMAC(bitLength, new byte[0]);
            this.outputBytes = defaultOutputBytes;
        }
        else if (params instanceof KMACParameterSpec)
        {
            KMACParameterSpec spec = (KMACParameterSpec)params;
            this.macEngine = new KMAC(bitLength, spec.getCustomizationString());
            this.outputBytes = spec.getMacSizeInBits() / 8;
        }
        else
        {
            throw new InvalidAlgorithmParameterException(
                "unknown parameter spec for KMAC: " + params.getClass().getName());
        }

        try
        {
            macEngine.init(new KeyParameter(encodedKey));
        }
        catch (IllegalArgumentException e)
        {
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }
    }

    protected int engineGetMacLength()
    {
        return outputBytes;
    }

    protected void engineUpdate(byte input)
    {
        macEngine.update(input);
    }

    protected void engineUpdate(byte[] input, int offset, int len)
    {
        macEngine.update(input, offset, len);
    }

    protected void engineReset()
    {
        macEngine.reset();
    }

    protected byte[] engineDoFinal()
    {
        byte[] out = new byte[outputBytes];
        macEngine.doFinal(out, 0, outputBytes);
        return out;
    }

    public static class KMac128
        extends KMacSpi
    {
        public KMac128()
        {
            super(128);
        }
    }

    public static class KMac256
        extends KMacSpi
    {
        public KMac256()
        {
            super(256);
        }
    }
}

package org.bouncycastle.jcajce.provider.kdf.kmac;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.spec.KMACKDFParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * javax.crypto.KDF SPI for the KMAC-based KDF of RFC 9629 / RFC 9935: the derived key is
 * KMAC(secret, context, L, customization). Each derivation builds a fresh KMAC, so a KDF instance may be
 * shared across threads.
 */
public class KMACKDFSpi
    extends KDFSpi
{
    private final int bitLength;

    KMACKDFSpi(KDFParameters kdfParameters, int bitLength)
        throws InvalidAlgorithmParameterException
    {
        super(requireNull(kdfParameters, "KMAC-KDF does not support parameters"));
        this.bitLength = bitLength;
    }

    @Override
    protected KDFParameters engineGetParameters()
    {
        return null;
    }

    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        byte[] derivedKey = engineDeriveData(derivationSpec);

        try
        {
            return new SecretKeySpec(derivedKey, alg);
        }
        finally
        {
            Arrays.clear(derivedKey);
        }
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec)
        throws InvalidAlgorithmParameterException
    {
        if (!(derivationSpec instanceof KMACKDFParameterSpec spec))
        {
            throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec provided");
        }

        byte[] secret = spec.getSecret();
        try
        {
            KMAC mac = new KMAC(bitLength, spec.getCustomization());
            byte[] context = spec.getContext();

            mac.init(new KeyParameter(secret));
            mac.update(context, 0, context.length);

            byte[] result = new byte[spec.getOutputLength()];
            mac.doFinal(result, 0, result.length);
            return result;
        }
        finally
        {
            Arrays.clear(secret);
        }
    }

    private static KDFParameters requireNull(KDFParameters kdfParameters, String message)
        throws InvalidAlgorithmParameterException
    {
        if (kdfParameters != null)
        {
            throw new InvalidAlgorithmParameterException(message);
        }
        return null;
    }

    public static class KMAC128 extends KMACKDFSpi
    {
        public KMAC128(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, 128);
        }

        public KMAC128() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }

    public static class KMAC256 extends KMACKDFSpi
    {
        public KMAC256(KDFParameters kdfParameters) throws InvalidAlgorithmParameterException
        {
            super(kdfParameters, 256);
        }

        public KMAC256() throws InvalidAlgorithmParameterException
        {
            this(null);
        }
    }
}

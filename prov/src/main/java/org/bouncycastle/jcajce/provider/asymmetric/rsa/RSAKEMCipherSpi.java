package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.jcajce.provider.asymmetric.util.WrapUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Exceptions;

/**
 * Cipher SPI implementing the ISO 18033-2 / RFC 9690 RSA-KEM key-transport scheme,
 * registered under the JCE service name {@code "RSA-KTS-KEM-KWS"} and aliased
 * against the {@code id-kem-rsa} object identifier (1.0.18033.2.2.4).
 * <p>
 * Driven by the CMS pipeline through
 * {@link org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator} (wrap) and
 * {@link org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient} (unwrap) when the
 * recipient holds an RSA key; the analogous peer for ML-KEM is
 * {@link org.bouncycastle.jcajce.provider.asymmetric.mlkem.MLKEMCipherSpi}.
 * <p>
 * Cipher operates in {@code WRAP_MODE} / {@code UNWRAP_MODE} only and requires a
 * {@link KTSParameterSpec} carrying the KDF (KDF2 / KDF3 / HKDF per RFC 9690
 * &sect;4) and the AES-Wrap variant. Wrap output is the RSA-KEM ciphertext
 * (modulus-byte length) concatenated with the AES-wrapped CEK; the CMS caller
 * splits them based on the modulus length.
 */
public class RSAKEMCipherSpi
    extends CipherSpi
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private RSAPublicKey wrapKey;
    private RSAPrivateKey unwrapKey;
    private KTSParameterSpec ktsSpec;
    private SecureRandom random;

    public RSAKEMCipherSpi()
    {
    }

    protected void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("Cannot support mode " + mode);
    }

    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("Padding " + padding + " unknown");
    }

    protected int engineGetKeySize(Key key)
    {
        if (key instanceof RSAPublicKey)
        {
            return ((RSAPublicKey)key).getModulus().bitLength();
        }
        if (key instanceof RSAPrivateKey)
        {
            return ((RSAPrivateKey)key).getModulus().bitLength();
        }
        throw new IllegalArgumentException("not an RSA key");
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected int engineGetOutputSize(int inputLen)
    {
        return -1;
    }

    protected byte[] engineGetIV()
    {
        return null;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw Exceptions.illegalArgumentException(e.getMessage(), e);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec paramSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (paramSpec == null)
        {
            throw new InvalidAlgorithmParameterException("RSA-KTS-KEM-KWS requires a KTSParameterSpec");
        }
        if (!(paramSpec instanceof KTSParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("RSA-KTS-KEM-KWS can only accept KTSParameterSpec");
        }

        this.ktsSpec = (KTSParameterSpec)paramSpec;

        if (opmode == Cipher.WRAP_MODE)
        {
            if (!(key instanceof RSAPublicKey))
            {
                throw new InvalidKeyException("Only an RSA public key can be used for wrapping");
            }
            this.wrapKey = (RSAPublicKey)key;
            this.unwrapKey = null;
            this.random = CryptoServicesRegistrar.getSecureRandom(random);
        }
        else if (opmode == Cipher.UNWRAP_MODE)
        {
            if (!(key instanceof RSAPrivateKey))
            {
                throw new InvalidKeyException("Only an RSA private key can be used for unwrapping");
            }
            this.unwrapKey = (RSAPrivateKey)key;
            this.wrapKey = null;
            this.random = null;
        }
        else
        {
            throw new InvalidParameterException("Cipher only valid for wrapping/unwrapping");
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (algorithmParameters != null)
        {
            try
            {
                paramSpec = algorithmParameters.getParameterSpec(KTSParameterSpec.class);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + algorithmParameters.toString());
            }
        }

        engineInit(opmode, key, paramSpec, random);
    }

    protected byte[] engineUpdate(byte[] bytes, int i, int i1)
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected byte[] engineDoFinal(byte[] bytes, int i, int i1)
        throws IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        throw new IllegalStateException("Not supported in a wrapping mode");
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException
    {
        if (wrapKey == null)
        {
            throw new IllegalStateException("Cipher not initialised for wrapping");
        }

        byte[] keyToWrap = key.getEncoded();
        if (keyToWrap == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        BigInteger n = wrapKey.getModulus();
        BigInteger e = wrapKey.getPublicExponent();
        int modLen = (n.bitLength() + 7) / 8;

        byte[] R = null;
        try
        {
            BigInteger r = BigIntegers.createRandomInRange(ZERO, n.subtract(ONE), random);
            BigInteger c = r.modPow(e, n);

            R = BigIntegers.asUnsignedByteArray(modLen, r);
            Wrapper kWrap = WrapUtil.getKeyWrapper(ktsSpec, R);

            try
            {
                byte[] wrapped = kWrap.wrap(keyToWrap, 0, keyToWrap.length);
                byte[] out = new byte[modLen + wrapped.length];
                BigIntegers.asUnsignedByteArray(c, out, 0, modLen);
                System.arraycopy(wrapped, 0, out, modLen, wrapped.length);
                return out;
            }
            finally
            {
                Arrays.clear(keyToWrap);
            }
        }
        catch (IllegalArgumentException ex)
        {
            throw new IllegalBlockSizeException("unable to generate KTS secret: " + ex.getMessage());
        }
        finally
        {
            if (R != null)
            {
                Arrays.clear(R);
            }
        }
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        if (unwrapKey == null)
        {
            throw new IllegalStateException("Cipher not initialised for unwrapping");
        }
        if (wrappedKeyType != Cipher.SECRET_KEY)
        {
            throw new InvalidKeyException("only SECRET_KEY supported");
        }

        BigInteger n = unwrapKey.getModulus();
        BigInteger d = unwrapKey.getPrivateExponent();
        int modLen = (n.bitLength() + 7) / 8;

        if (wrappedKey.length < modLen)
        {
            throw new InvalidKeyException("wrapped key too short for modulus");
        }

        byte[] R = null;
        try
        {
            BigInteger c = BigIntegers.fromUnsignedByteArray(wrappedKey, 0, modLen);
            BigInteger r = c.modPow(d, n);

            R = BigIntegers.asUnsignedByteArray(modLen, r);
            Wrapper kWrap = WrapUtil.getKeyUnwrapper(ktsSpec, R);

            return new SecretKeySpec(kWrap.unwrap(wrappedKey, modLen, wrappedKey.length - modLen), wrappedKeyAlgorithm);
        }
        catch (IllegalArgumentException ex)
        {
            throw new NoSuchAlgorithmException("unable to extract KTS secret: " + ex.getMessage());
        }
        catch (InvalidCipherTextException ex)
        {
            throw new InvalidKeyException("unable to extract KTS secret: " + ex.getMessage());
        }
        finally
        {
            if (R != null)
            {
                Arrays.clear(R);
            }
        }
    }
}

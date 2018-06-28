package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public abstract class BaseCipherSpi
    extends CipherSpi
{
    //
    // specs we can handle.
    //
    private Class[]                 availableSpecs =
                                    {
                                        IvParameterSpec.class,
                                        PBEParameterSpec.class,
                                        RC2ParameterSpec.class,
                                        RC5ParameterSpec.class
                                    };

    private final JcaJceHelper helper = new BCJcaJceHelper();

    protected AlgorithmParameters     engineParams = null;

    protected Wrapper                 wrapEngine = null;

    private int                       ivSize;
    private byte[]                    iv;

    protected BaseCipherSpi()
    {
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected byte[] engineGetIV()
    {
        return null;
    }

    protected int engineGetKeySize(
        Key     key)
    {
        return key.getEncoded().length;
    }

    protected int engineGetOutputSize(
        int     inputLen)
    {
        return -1;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    protected final AlgorithmParameters createParametersInstance(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return helper.createAlgorithmParameters(algorithm);
    }

    protected void engineSetMode(
        String  mode)
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    protected void engineSetPadding(
        String  padding)
    throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException("Padding " + padding + " unknown.");
    }

    protected byte[] engineWrap(
        Key     key)
    throws IllegalBlockSizeException, InvalidKeyException
    {
        byte[] encoded = key.getEncoded();
        if (encoded == null)
        {
            throw new InvalidKeyException("Cannot wrap key, null encoding.");
        }

        try
        {
            if (wrapEngine == null)
            {
                return engineDoFinal(encoded, 0, encoded.length);
            }
            else
            {
                return wrapEngine.wrap(encoded, 0, encoded.length);
            }
        }
        catch (BadPaddingException e)
        {
            throw new IllegalBlockSizeException(e.getMessage());
        }
    }

    protected Key engineUnwrap(
        byte[]  wrappedKey,
        String  wrappedKeyAlgorithm,
        int     wrappedKeyType)
    throws InvalidKeyException
    {
        byte[] encoded;
        try
        {
            if (wrapEngine == null)
            {
                encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            }
            else
            {
                encoded = wrapEngine.unwrap(wrappedKey, 0, wrappedKey.length);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw new InvalidKeyException(e.getMessage());
        }
        catch (final BadPaddingException e)
        {
            throw new InvalidKeyException("unable to unwrap")
            {
                public synchronized Throwable getCause()
                {
                    return e;
                }
            };
        }
        catch (IllegalBlockSizeException e2)
        {
            throw new InvalidKeyException(e2.getMessage());
        }

        if (wrappedKeyType == Cipher.SECRET_KEY)
        {
            return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
        }
        else if (wrappedKeyAlgorithm.equals("") && wrappedKeyType == Cipher.PRIVATE_KEY)
        {
            /*
                 * The caller doesn't know the algorithm as it is part of
                 * the encrypted data.
                 */
            try
            {
                PrivateKeyInfo       in = PrivateKeyInfo.getInstance(encoded);

                PrivateKey privKey = BouncyCastleProvider.getPrivateKey(in);

                if (privKey != null)
                {
                    return privKey;
                }
                else
                {
                    throw new InvalidKeyException("algorithm " + in.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("Invalid key encoding.");
            }
        }
        else
        {
            try
            {
                KeyFactory kf = helper.createKeyFactory(wrappedKeyAlgorithm);

                if (wrappedKeyType == Cipher.PUBLIC_KEY)
                {
                    return kf.generatePublic(new X509EncodedKeySpec(encoded));
                }
                else if (wrappedKeyType == Cipher.PRIVATE_KEY)
                {
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                }
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new InvalidKeyException("Unknown key type " + e.getMessage());
            }
            catch (InvalidKeySpecException e)
            {
                throw new InvalidKeyException("Unknown key type " + e.getMessage());
            }
            catch (NoSuchProviderException e)
            {
                throw new InvalidKeyException("Unknown key type " + e.getMessage());
            }

            throw new InvalidKeyException("Unknown key type " + wrappedKeyType);
        }
    }

    protected static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        public ErasableOutputStream()
        {
        }

        public byte[] getBuf()
        {
            return buf;
        }

        public void erase()
        {
            Arrays.fill(this.buf, (byte)0);
            reset();
        }
    }
}

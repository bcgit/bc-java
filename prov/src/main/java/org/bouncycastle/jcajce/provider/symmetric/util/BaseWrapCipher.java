package org.bouncycastle.jcajce.provider.symmetric.util;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public abstract class BaseWrapCipher
    extends CipherSpi
    implements PBE
{
    //
    // specs we can handle.
    //
    private Class[]                 availableSpecs =
                                    {
                                        GOST28147WrapParameterSpec.class,
                                        PBEParameterSpec.class,
                                        RC2ParameterSpec.class,
                                        RC5ParameterSpec.class,
                                        IvParameterSpec.class
                                    };

    protected int                     pbeType = PKCS12;
    protected int                     pbeHash = SHA1;
    protected int                     pbeKeySize;
    protected int                     pbeIvSize;

    protected AlgorithmParameters     engineParams = null;

    protected Wrapper                 wrapEngine = null;

    private int                       ivSize;
    private byte[]                    iv;

    private ErasableOutputStream wrapStream = null;
    private boolean                   forWrapping;

    private final JcaJceHelper helper = new BCJcaJceHelper();

    protected BaseWrapCipher()
    {
    }

    protected BaseWrapCipher(
        Wrapper wrapEngine)
    {
        this(wrapEngine, 0);
    }

    protected BaseWrapCipher(
        Wrapper wrapEngine,
        int ivSize)
    {
        this.wrapEngine = wrapEngine;
        this.ivSize = ivSize;
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    protected byte[] engineGetIV()
    {
        return Arrays.clone(iv);
    }

    protected int engineGetKeySize(
        Key     key)
    {
        return key.getEncoded().length * 8;
    }

    protected int engineGetOutputSize(
        int     inputLen)
    {
        return -1;
    }

    protected AlgorithmParameters engineGetParameters()
    {
        if (engineParams == null)
        {
            if (iv != null)
            {
                String  name = wrapEngine.getAlgorithmName();

                if (name.indexOf('/') >= 0)
                {
                    name = name.substring(0, name.indexOf('/'));
                }

                try
                {
                    engineParams = createParametersInstance(name);
                    engineParams.init(new IvParameterSpec(iv));
                }
                catch (Exception e)
                {
                    throw new RuntimeException(e.toString());
                }
            }
        }

        return engineParams;
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

    protected void engineInit(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        CipherParameters        param;

        if (key instanceof BCPBEKey)
        {
            BCPBEKey k = (BCPBEKey)key;

            if (params instanceof PBEParameterSpec)
            {
                param = PBE.Util.makePBEParameters(k, params, wrapEngine.getAlgorithmName());
            }
            else if (k.getParam() != null)
            {
                param = k.getParam();
            }
            else
            {
                throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
            }
        }
        else
        {
            param = new KeyParameter(key.getEncoded());
        }

        if (params instanceof IvParameterSpec)
        {
            IvParameterSpec ivSpec = (IvParameterSpec)params;
            this.iv = ivSpec.getIV();
            param = new ParametersWithIV(param, iv);
        }

        if (params instanceof GOST28147WrapParameterSpec)
        {
            GOST28147WrapParameterSpec spec = (GOST28147WrapParameterSpec) params;

            byte[] sBox = spec.getSBox();
            if (sBox != null)
            {
                param = new ParametersWithSBox(param, sBox);
            }
            param = new ParametersWithUKM(param, spec.getUKM());
        }

        if (param instanceof KeyParameter && ivSize != 0)
        {
            if (opmode == Cipher.WRAP_MODE || opmode == Cipher.ENCRYPT_MODE)
            {
                iv = new byte[ivSize];
                random.nextBytes(iv);
                param = new ParametersWithIV(param, iv);
            }
        }

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }

        try
        {
            switch (opmode)
            {
            case Cipher.WRAP_MODE:
                wrapEngine.init(true, param);
                this.wrapStream = null;
                this.forWrapping = true;
                break;
            case Cipher.UNWRAP_MODE:
                wrapEngine.init(false, param);
                this.wrapStream = null;
                this.forWrapping = false;
                break;
            case Cipher.ENCRYPT_MODE:
                wrapEngine.init(true, param);
                this.wrapStream = new ErasableOutputStream();
                this.forWrapping = true;
                break;
            case Cipher.DECRYPT_MODE:
                wrapEngine.init(false, param);
                this.wrapStream = new ErasableOutputStream();
                this.forWrapping = false;
                break;
            default:
                throw new InvalidParameterException("Unknown mode parameter passed to init.");
            }
        }
        catch (Exception e)
        {
            throw new InvalidKeyOrParametersException(e.getMessage(), e);
        }
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random)
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec  paramSpec = null;

        if (params != null)
        {
            paramSpec = SpecUtil.extractSpec(params, availableSpecs);

            if (paramSpec == null)
            {
                throw new InvalidAlgorithmParameterException("can't handle parameter " + params.toString());
            }
        }

        engineParams = params;
        engineInit(opmode, key, paramSpec, random);
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        SecureRandom        random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyOrParametersException(e.getMessage(), e);
        }
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        wrapStream.write(input, inputOffset, inputLen);

        return null;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws ShortBufferException
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        wrapStream.write(input, inputOffset, inputLen);

        return 0;
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        if (input != null)
        {
            wrapStream.write(input, inputOffset, inputLen);
        }

        try
        {
            if (forWrapping)
            {
                try
                {
                    return wrapEngine.wrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (Exception e)
                {
                    throw new IllegalBlockSizeException(e.getMessage());
                }
            }
            else
            {
                try
                {
                    return wrapEngine.unwrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (InvalidCipherTextException e)
                {
                    throw new BadPaddingException(e.getMessage());
                }
            }
        }
        finally
        {
            wrapStream.erase();
        }
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset)
        throws IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
        if (wrapStream == null)
        {
            throw new IllegalStateException("not supported in a wrapping mode");
        }

        wrapStream.write(input, inputOffset, inputLen);

        try
        {
            byte[] enc;

            if (forWrapping)
            {
                try
                {
                    enc = wrapEngine.wrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (Exception e)
                {
                    throw new IllegalBlockSizeException(e.getMessage());
                }
            }
            else
            {
                try
                {
                    enc = wrapEngine.unwrap(wrapStream.getBuf(), 0, wrapStream.size());
                }
                catch (InvalidCipherTextException e)
                {
                    throw new BadPaddingException(e.getMessage());
                }
            }

            if (outputOffset + enc.length > output.length)
            {
                throw new ShortBufferException("output buffer too short for input.");
            }

            System.arraycopy(enc, 0, output, outputOffset, enc.length);

            return enc.length;
        }
        finally
        {
            wrapStream.erase();
        }
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
    throws InvalidKeyException, NoSuchAlgorithmException
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
        catch (BadPaddingException e)
        {
            throw new InvalidKeyException(e.getMessage());
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
            catch (NoSuchProviderException e)
            {
                throw new InvalidKeyException("Unknown key type " + e.getMessage());
            }
            catch (InvalidKeySpecException e2)
            {
                throw new InvalidKeyException("Unknown key type " + e2.getMessage());
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

    protected static class InvalidKeyOrParametersException
        extends InvalidKeyException
    {
        private final Throwable cause;

        InvalidKeyOrParametersException(String msg, Throwable cause)
        {
             super(msg);
            this.cause = cause;
        }

        public Throwable getCause()
        {
            return cause;
        }
    }
}

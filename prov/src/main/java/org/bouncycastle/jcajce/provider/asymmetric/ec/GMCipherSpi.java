package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;


public class GMCipherSpi
    extends CipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private SM2Engine engine;
    private int state = -1;
    private ErasableOutputStream buffer = new ErasableOutputStream();
    private AsymmetricKeyParameter key;
    private SecureRandom random;

    public GMCipherSpi(SM2Engine engine)
    {
        this.engine = engine;
    }

    public int engineGetBlockSize()
    {
        return 0;
    }

    public int engineGetKeySize(Key key)
    {
        if (key instanceof ECKey)
        {
            return ((ECKey)key).getParameters().getCurve().getFieldSize();
        }
        else
        {
            throw new IllegalArgumentException("not an EC key");
        }
    }


    public byte[] engineGetIV()
    {
        return null;
    }

    public AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    public void engineSetMode(String mode)
        throws NoSuchAlgorithmException
    {
        String modeName = Strings.toUpperCase(mode);

        if (!modeName.equals("NONE"))
        {
            throw new IllegalArgumentException("can't support mode " + mode);
        }
    }

    public int engineGetOutputSize(int inputLen)
    {
        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            return engine.getOutputSize(inputLen);
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            return engine.getOutputSize(inputLen);
        }
        else
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    public void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        String paddingName = Strings.toUpperCase(padding);

        // TDOD: make this meaningful...
        if (!paddingName.equals("NOPADDING"))
        {
            throw new NoSuchPaddingException("padding not available with IESCipher");
        }
    }


    // Initialisation methods

    public void engineInit(
        int opmode,
        Key key,
        AlgorithmParameters params,
        SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec paramSpec = null;

        if (params != null)
        {
            throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + params.getClass().getName());
        }

        engineInit(opmode, key, paramSpec, random);
    }

    public void engineInit(
        int opmode,
        Key key,
        AlgorithmParameterSpec engineSpec,
        SecureRandom random)
        throws InvalidAlgorithmParameterException, InvalidKeyException
    {
        // Parse the recipient's key
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)
        {
            if (key instanceof PublicKey)
            {
                this.key = ECUtils.generatePublicKeyParameter((PublicKey)key);
            }
            else
            {
                throw new InvalidKeyException("must be passed public EC key for encryption");
            }
        }
        else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE)
        {
            if (key instanceof PrivateKey)
            {
                this.key = ECUtil.generatePrivateKeyParameter((PrivateKey)key);
            }
            else
            {
                throw new InvalidKeyException("must be passed private EC key for decryption");
            }
        }
        else
        {
            throw new InvalidKeyException("must be passed EC key");
        }


        if (random != null)
        {
            this.random = random;
        }
        else
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        this.state = opmode;
        buffer.reset();
    }

    public void engineInit(
        int opmode,
        Key key,
        SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new IllegalArgumentException("cannot handle supplied parameter spec: " + e.getMessage());
        }
    }


    // Update methods - buffer the input

    public byte[] engineUpdate(
        byte[] input,
        int inputOffset,
        int inputLen)
    {
        buffer.write(input, inputOffset, inputLen);
        return null;
    }


    public int engineUpdate(
        byte[] input,
        int inputOffset,
        int inputLen,
        byte[] output,
        int outputOffset)
    {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }


    // Finalisation methods

    public byte[] engineDoFinal(
        byte[] input,
        int inputOffset,
        int inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (inputLen != 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }

        try
        {
            if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
            {
                // Encrypt the buffer
                try
                {
                    engine.init(true, new ParametersWithRandom(key, random));

                    return engine.processBlock(buffer.getBuf(), 0, buffer.size());
                }
                catch (final Exception e)
                {
                    throw new BadBlockException("unable to process block", e);
                }
            }
            else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
            {
                // Decrypt the buffer
                try
                {
                    engine.init(false, key);

                    return engine.processBlock(buffer.getBuf(), 0, buffer.size());
                }
                catch (final Exception e)
                {
                    throw new BadBlockException("unable to process block", e);
                }
            }
            else
            {
                throw new IllegalStateException("cipher not initialised");
            }
        }
        finally
        {
            buffer.erase();
        }
    }

    public int engineDoFinal(
        byte[] input,
        int inputOffset,
        int inputLength,
        byte[] output,
        int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] buf = engineDoFinal(input, inputOffset, inputLength);
        System.arraycopy(buf, 0, output, outputOffset, buf.length);
        return buf.length;
    }

    /**
     * Classes that inherit from us
     */
    static public class SM2
        extends GMCipherSpi
    {
        public SM2()
        {
            super(new SM2Engine());
        }
    }

    static public class SM2withBlake2b
        extends GMCipherSpi
    {
        public SM2withBlake2b()
        {
            super(new SM2Engine(new Blake2bDigest(512)));
        }
    }

    static public class SM2withBlake2s
        extends GMCipherSpi
    {
        public SM2withBlake2s()
        {
            super(new SM2Engine(new Blake2sDigest(256)));
        }
    }

    static public class SM2withWhirlpool
        extends GMCipherSpi
    {
        public SM2withWhirlpool()
        {
            super(new SM2Engine(new WhirlpoolDigest()));
        }
    }

    static public class SM2withMD5
        extends GMCipherSpi
    {
        public SM2withMD5()
        {
            super(new SM2Engine(new MD5Digest()));
        }
    }

    static public class SM2withRMD
        extends GMCipherSpi
    {
        public SM2withRMD()
        {
            super(new SM2Engine(new RIPEMD160Digest()));
        }
    }

    static public class SM2withSha1
        extends GMCipherSpi
    {
        public SM2withSha1()
        {
            super(new SM2Engine(new SHA1Digest()));
        }
    }

    static public class SM2withSha224
        extends GMCipherSpi
    {
        public SM2withSha224()
        {
            super(new SM2Engine(new SHA224Digest()));
        }
    }

    static public class SM2withSha256
        extends GMCipherSpi
    {
        public SM2withSha256()
        {
            super(new SM2Engine(new SHA256Digest()));
        }
    }

    static public class SM2withSha384
        extends GMCipherSpi
    {
        public SM2withSha384()
        {
            super(new SM2Engine(new SHA384Digest()));
        }
    }

    static public class SM2withSha512
        extends GMCipherSpi
    {
        public SM2withSha512()
        {
            super(new SM2Engine(new SHA512Digest()));
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

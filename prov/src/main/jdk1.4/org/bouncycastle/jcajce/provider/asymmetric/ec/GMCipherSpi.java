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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseCipherSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;


public class GMCipherSpi
    extends BaseCipherSpi
{
    private final JcaJceHelper helper = new BCJcaJceHelper();

    private final Digest digest;
    private int mode = SM2Engine.C1C2C3;
    private SM2Engine engine;
    private int state = -1;
    private ErasableOutputStream buffer = new ErasableOutputStream();
    private AsymmetricKeyParameter key;
    private SecureRandom random;

    public GMCipherSpi(Digest digest)
    {
        this.digest = digest;
        this.engine = new SM2Engine(digest, mode);
    }

    public int engineGetBlockSize()
    {
        return 0;
    }

    /**
     * The field size of the key's curve, for any EC key init accepts - not just a BC one - so the key
     * is converted the same way init converts it. Cipher asks for the size before init sees the key,
     * so a key that is not an EC key is answered as BaseCipherSpi answers it, and left for init to
     * refuse with the InvalidKeyException it declares.
     */
    public int engineGetKeySize(Key key)
    {
        try
        {
            if (key instanceof PublicKey)
            {
                return fieldSize(ECUtils.generatePublicKeyParameter((PublicKey)key));
            }
            if (key instanceof PrivateKey)
            {
                return fieldSize(ECUtil.generatePrivateKeyParameter((PrivateKey)key));
            }
        }
        catch (InvalidKeyException e)
        {
            // not an EC key init would take
        }
        return super.engineGetKeySize(key);
    }

    private static int fieldSize(AsymmetricKeyParameter keyParam)
    {
        return ((ECKeyParameters)keyParam).getParameters().getCurve().getFieldSize();
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

        if (modeName.equals("NONE") || modeName.equals("C1C2C3"))
        {
            this.mode = SM2Engine.C1C2C3;
        }
        else if (modeName.equals("C1C3C2"))
        {
            this.mode = SM2Engine.C1C3C2;
        }
        else
        {
            throw new NoSuchAlgorithmException("can't support mode " + mode);
        }

        this.engine = new SM2Engine(digest, this.mode);
    }

    /**
     * The size of the next doFinal's output, which takes the input update() has buffered as well as
     * inputLen more. C2 is as long as the message and C1 and C3 are of fixed size, so the answer is
     * exact: encryption adds that overhead and decryption removes it. The sum is taken in long and
     * capped at the largest array.
     */
    public int engineGetOutputSize(int inputLen)
    {
        if (state == Cipher.ENCRYPT_MODE || state == Cipher.WRAP_MODE)
        {
            return outputSize((long)buffer.size() + inputLen + overhead());
        }
        else if (state == Cipher.DECRYPT_MODE || state == Cipher.UNWRAP_MODE)
        {
            return outputSize(Math.max((long)buffer.size() + inputLen - overhead(), 0L));
        }
        else
        {
            throw new IllegalStateException("cipher not initialised");
        }
    }

    /**
     * The size of C1, an uncompressed point of the key's curve, and C3, a digest. Taken from the key
     * rather than the engine, which learns the curve only when doFinal initialises it, so asking the
     * engine before the first doFinal answered short by the two coordinates.
     */
    private long overhead()
    {
        return 1 + 2L * ((ECKeyParameters)key).getParameters().getCurve().getFieldElementEncodingLength()
            + digest.getDigestSize();
    }

    private static int outputSize(long size)
    {
        return (size > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int)size;
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
            // a refused init ends the operation in progress as well, and this one is refused before
            // reaching the init below, which zeroes what that operation had buffered
            buffer.erase();
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
        // An init ends the operation in progress whether or not it succeeds, and what that
        // operation had buffered - on encryption, the plaintext - is zeroed rather than only
        // rewound, which left it in the backing array
        buffer.erase();

        // Nothing about the cipher is set at init - the mode and the digest come from the
        // transformation - so a spec is refused: ignored, whatever the caller believed it was
        // applying was silently dropped
        if (engineSpec != null)
        {
            throw new InvalidAlgorithmParameterException(
                "SM2 cipher takes no AlgorithmParameterSpec: " + engineSpec.getClass().getName());
        }

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
            throw Exceptions.illegalArgumentException("cannot handle supplied parameter spec", e);
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
        // The output size is known exactly beforehand, so the array is checked before the operation
        // runs: running it consumes the buffered input, and the JCA contract for ShortBufferException
        // is that the call can be retried with a larger array. The result's own copy - on
        // decryption the plaintext - is erased once the caller has theirs.
        if (engineGetOutputSize(inputLength) > output.length - outputOffset)
        {
            throw new ShortBufferException("output buffer too short");
        }
        byte[] buf = engineDoFinal(input, inputOffset, inputLength);
        try
        {
            System.arraycopy(buf, 0, output, outputOffset, buf.length);
            return buf.length;
        }
        finally
        {
            Arrays.fill(buf, (byte)0);
        }
    }

    /**
     * Classes that inherit from us
     */
    static public class SM2
        extends GMCipherSpi
    {
        public SM2()
        {
            super(new SM3Digest());
        }
    }

    static public class SM2withBlake2b
        extends GMCipherSpi
    {
        public SM2withBlake2b()
        {
            super(new Blake2bDigest(512));
        }
    }

    static public class SM2withBlake2s
        extends GMCipherSpi
    {
        public SM2withBlake2s()
        {
            super(new Blake2sDigest(256));
        }
    }

    static public class SM2withWhirlpool
        extends GMCipherSpi
    {
        public SM2withWhirlpool()
        {
            super(new WhirlpoolDigest());
        }
    }

    static public class SM2withMD5
        extends GMCipherSpi
    {
        public SM2withMD5()
        {
            super(new MD5Digest());
        }
    }

    static public class SM2withRMD
        extends GMCipherSpi
    {
        public SM2withRMD()
        {
            super(new RIPEMD160Digest());
        }
    }

    static public class SM2withSha1
        extends GMCipherSpi
    {
        public SM2withSha1()
        {
            super(new SHA1Digest());
        }
    }

    static public class SM2withSha224
        extends GMCipherSpi
    {
        public SM2withSha224()
        {
            super(new SHA224Digest());
        }
    }

    static public class SM2withSha256
        extends GMCipherSpi
    {
        public SM2withSha256()
        {
            super(SHA256Digest.newInstance());
        }
    }

    static public class SM2withSha384
        extends GMCipherSpi
    {
        public SM2withSha384()
        {
            super(new SHA384Digest());
        }
    }

    static public class SM2withSha512
        extends GMCipherSpi
    {
        public SM2withSha512()
        {
            super(new SHA512Digest());
        }
    }

    /**
     * A ByteArrayOutputStream whose contents can be zeroed: reset() only rewinds the count and
     * leaves what was written in the backing array, and a growth, left to ByteArrayOutputStream,
     * drops the array it replaces as it stands. The SM9 CipherSpi carries the same class.
     */
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

        public synchronized void write(int b)
        {
            reserve(1);
            buf[count++] = (byte)b;
        }

        public synchronized void write(byte[] b, int off, int len)
        {
            if (off < 0 || len < 0 || off > b.length - len)
            {
                throw new IndexOutOfBoundsException();
            }
            reserve(len);
            System.arraycopy(b, off, buf, count, len);
            count += len;
        }

        /**
         * Make room for len more bytes. ByteArrayOutputStream grows by copying its contents into a
         * larger array and dropping the old one as it stands, which would leave a copy of what has
         * been written so far where erase() never reaches; the array replaced here is zeroed once
         * its contents have been copied.
         */
        private void reserve(int len)
        {
            if (len > buf.length - count)
            {
                if (len > Integer.MAX_VALUE - count)
                {
                    throw new OutOfMemoryError();
                }
                byte[] grown = new byte[Math.max(count + len, buf.length << 1)];
                System.arraycopy(buf, 0, grown, 0, count);
                Arrays.fill(buf, (byte)0);
                buf = grown;
            }
        }
    }
}

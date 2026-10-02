package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.gm.SM9Cipher;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.crypto.engines.SM9Engine;
import org.bouncycastle.jcajce.provider.util.SecurityExceptions;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * JCA {@link javax.crypto.Cipher} for SM9 public-key encryption (GM/T 0044.4).
 * <p>
 * Encrypt with the recipient's public key, formed from the published master public key
 * and the recipient's identity via
 * {@link org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey#getUserPublicKey(byte[])};
 * decrypt with the recipient's private key. The default data-encapsulation mode is
 * SM4/ECB/PKCS#7 ({@code enType} = 1), which {@code Cipher.getInstance("SM9")} gives; the KDF
 * stream mode is selected with the transformation {@code "SM9/XOR/NoPadding"}. The
 * transformation's padding is always {@code NoPadding}: the SM4 mode's PKCS#7 is part of
 * GM/T 0044.4's data encapsulation, applied inside the mechanism, not a padding the caller
 * chooses, so {@code "SM9/SM4/PKCS7Padding"} is refused rather than taken as a second name for
 * the default.
 * <p>
 * The SM4 mode is ECB with no IV, as in the Chinese edition's GM/T 0044.5-2016 Annex D.1
 * example. The official English edition and GB/T 38635.2-2020 describe this method differently
 * (CBC with a zero IV; and a 16-byte IV carried at the front of C2), so a peer built from either
 * does not interoperate with it - see {@link SM9Engine.Mode#SM4}.
 * <p>
 * The mode applies to decryption as well as encryption: the ciphertext is a DER
 * {@link SM9Cipher} whose {@code enType} records the mode, and the mode this {@code Cipher}
 * was configured with decides - a stream-mode ciphertext is decrypted through a stream-mode
 * {@code Cipher} ({@code "SM9/XOR/NoPadding"}), an SM4-mode one through the default - and a
 * ciphertext whose {@code enType} disagrees with it is rejected as malformed. Neither mode
 * produces or accepts a 16-byte C2 (see {@link SM9Engine}): a stream-mode message of exactly
 * 16 bytes and an SM4-mode message of fewer than 16 bytes are refused on encryption, so the
 * first has to be sent in SM4 mode and the second in stream mode.
 * <p>
 * <b>Usage warning:</b> an identity's key should be used for this service or for the SM9
 * KEM ({@code KeyGenerator.SM9-KEM}, {@code KEM.SM9-KEM}), but not for both. A deployment
 * needing both has its KGC publish a separate hid for each function, as it already does for
 * the key exchange, so that the two keys are distinct.
 * <p>
 * The ciphertext is the GM/T 0080-2020 SM9Cipher structure (see {@link org.bouncycastle.asn1.gm.SM9Cipher}).
 */
public class CipherSpi
    extends javax.crypto.CipherSpi
{
    // holds the plaintext on the encrypt path, so it is zeroed, not just rewound, once used
    private final ErasableOutputStream buffer = new ErasableOutputStream();

    private int state = -1;
    private SM9Engine.Mode mode = SM9Engine.Mode.SM4;
    private SM9EncPublicKeyParameters recipient;
    private SM9EncPrivateKeyParameters userKey;
    private SecureRandom random;

    protected void engineSetMode(String modeName)
        throws NoSuchAlgorithmException
    {
        String m = modeName == null ? "" : Strings.toUpperCase(modeName);
        if (m.equals("SM4") || m.equals("ECB") || m.equals(""))
        {
            mode = SM9Engine.Mode.SM4;
        }
        else if (m.equals("XOR") || m.equals("STREAM") || m.equals("KDF"))
        {
            mode = SM9Engine.Mode.STREAM;
        }
        else
        {
            throw new NoSuchAlgorithmException("unsupported SM9 mode: " + modeName);
        }
    }

    protected void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        if (padding != null && !padding.equalsIgnoreCase("NoPadding"))
        {
            throw new NoSuchPaddingException("padding not supported: " + padding);
        }
    }

    protected int engineGetBlockSize()
    {
        return 0;
    }

    /**
     * The size of an SM9 key: the 256 bits of the curve the scheme is defined on, as the EC ciphers
     * answer with their curve's field size. javax.crypto.Cipher asks for it when a restricted crypto
     * policy caps the key sizes it allows, and javax.crypto.CipherSpi's default threw
     * UnsupportedOperationException, which escaped Cipher.init in place of the InvalidKeyException it
     * declares.
     */
    protected int engineGetKeySize(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCSM9EncPublicKey || key instanceof BCSM9EncPrivateKey)
        {
            return SM9Curve.G1.getFieldSize();
        }
        throw new InvalidKeyException("not an SM9 encryption key");
    }

    protected int engineGetOutputSize(int inputLen)
    {
        // C1 point + C3 MAC + C2 (+ SM4 block rounding) + DER overhead; over-estimate. The answer is
        // for the next doFinal, which also takes the input update() has buffered, so that counts
        // too; the sum is taken in long so it cannot wrap, and is capped at the largest array.
        long size = (long)buffer.size() + inputLen + 256;
        return (size > Integer.MAX_VALUE) ? Integer.MAX_VALUE : (int)size;
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
            throw SecurityExceptions.invalidKeyException(e.getMessage(), e);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        this.state = opmode;
        this.random = CryptoServicesRegistrar.getSecureRandom(random);
        this.recipient = null;
        this.userKey = null;
        buffer.erase();

        if (opmode == Cipher.ENCRYPT_MODE)
        {
            if (params != null)
            {
                throw new InvalidAlgorithmParameterException(
                    "SM9 encryption takes no AlgorithmParameterSpec; encrypt to the recipient's public key from SM9EncMasterPublicKey.getUserPublicKey()");
            }
            if (!(key instanceof BCSM9EncPublicKey))
            {
                throw new InvalidKeyException(
                    "SM9 encryption requires the recipient's public key from SM9EncMasterPublicKey.getUserPublicKey()");
            }
            SM9EncPublicKeyParameters keyParams = ((BCSM9EncPublicKey)key).getKeyParameters();
            if (keyParams.getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE)
            {
                // the engine refuses it as well, but only once doFinal builds it; refused here, where
                // init can report the wrong kind of key as InvalidKeyException
                throw new InvalidKeyException(
                    "SM9 encryption requires an encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)");
            }
            recipient = keyParams;
        }
        else if (opmode == Cipher.DECRYPT_MODE)
        {
            if (params != null)
            {
                // refused as encryption refuses it: taken and ignored, an IV or other parameter the
                // caller believed it was applying was silently dropped
                throw new InvalidAlgorithmParameterException(
                    "SM9 decryption takes no AlgorithmParameterSpec; decrypt with the recipient's user private key alone");
            }
            if (!(key instanceof BCSM9EncPrivateKey))
            {
                throw new InvalidKeyException("SM9 decryption requires an SM9 user decryption key");
            }
            if (((BCSM9EncPrivateKey)key).isDestroyed())
            {
                // refused here rather than taken and left to fail in doFinal, where it came out as a
                // BadPaddingException blaming the ciphertext
                throw new InvalidKeyException("key destroyed");
            }
            SM9EncPrivateKeyParameters keyParams = ((BCSM9EncPrivateKey)key).getKeyParameters();
            if (keyParams.isExchangeKey())
            {
                // the engine refuses a key-exchange key as well, but only once doFinal builds it,
                // where the refusal came out as a BadPaddingException blaming the ciphertext; the
                // key is the wrong kind of key, which init and InvalidKeyException are for, as in
                // the KEM and key agreement services
                throw new InvalidKeyException("SM9 decryption requires an encryption user key, not a key-exchange key");
            }
            userKey = keyParams;
        }
        else if (opmode == Cipher.WRAP_MODE || opmode == Cipher.UNWRAP_MODE)
        {
            // javax.crypto.Cipher.init gives UnsupportedOperationException for a wrap or unwrap
            // mode the CipherSpi does not implement, and InvalidParameterException for an opmode
            // that is none of the four, which it refuses before the SPI is reached
            throw new UnsupportedOperationException("SM9 cipher supports only ENCRYPT_MODE and DECRYPT_MODE");
        }
        else
        {
            throw new InvalidParameterException("SM9 cipher supports only ENCRYPT_MODE and DECRYPT_MODE");
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            // a refused init ends the operation in progress as well, and this one is refused before
            // reaching the init below, which zeroes what that operation had buffered
            buffer.erase();
            throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported for SM9");
        }
        engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        if (input != null && inputLen > 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }
        return new byte[0];
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
    {
        engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException
    {
        if (state == Cipher.DECRYPT_MODE && userKey != null && userKey.isDestroyed())
        {
            // the key is refused at init; one destroyed since cannot decrypt, which is no fault of
            // the ciphertext - the BadPaddingException below says a ciphertext is malformed - so it
            // is reported as the state of the Cipher
            buffer.erase();
            throw new IllegalStateException("key destroyed");
        }
        if (input != null && inputLen > 0)
        {
            buffer.write(input, inputOffset, inputLen);
        }

        try
        {
            int enType = (mode == SM9Engine.Mode.SM4) ? SM9Cipher.EN_TYPE_SM4 : SM9Cipher.EN_TYPE_STREAM;

            if (state == Cipher.ENCRYPT_MODE)
            {
                SM9Engine engine = new SM9Engine(mode);
                engine.init(true, new ParametersWithRandom(recipient, random));
                // the plaintext is read where it was buffered, rather than copied out to an array
                // nothing would clear
                byte[] raw = engine.processBlock(buffer.getBuf(), 0, buffer.size());   // C1(64) || C3(32) || C2
                byte[] c1 = new byte[65];
                c1[0] = 0x04;
                System.arraycopy(raw, 0, c1, 1, 64);
                byte[] c3 = Arrays.copyOfRange(raw, 64, 96);
                byte[] c2 = Arrays.copyOfRange(raw, 96, raw.length);
                return new SM9Cipher(enType, c1, c3, c2).getEncoded();
            }
            else
            {
                byte[] data = buffer.toByteArray();   // the ciphertext
                SM9Cipher c = SM9Cipher.getInstance(data);
                if (c.getEnType() != enType)
                {
                    // the mode this Cipher was configured with decides, not the ciphertext's enType
                    throw new InvalidCipherTextException("SM9 ciphertext enType does not match the configured mode");
                }
                byte[] c1 = c.getC1();   // 0x04 || x || y
                byte[] c3 = c.getC3();
                if (c1.length != 65 || c1[0] != 0x04 || c3.length != 32
                    || !Arrays.areEqual(c.getEncoded(ASN1Encoding.DER), data))
                {
                    // only the encoding encryption produces is taken: the parse alone also accepts a
                    // non-minimal length, C1 would be read at fixed offsets whatever its prefix byte
                    // and length, and C3 and C2 could trade bytes across their field boundary - none
                    // of which changes the C1 || C3 || C2 the engine is handed
                    throw new InvalidCipherTextException("non-canonical SM9 ciphertext encoding");
                }
                byte[] raw = Arrays.concatenate(Arrays.copyOfRange(c1, 1, 65), c3, c.getC2());
                SM9Engine engine = new SM9Engine(mode);
                engine.init(false, userKey);
                return engine.processBlock(raw, 0, raw.length);
            }
        }
        catch (InvalidCipherTextException e)
        {
            throw SecurityExceptions.badPaddingException(
                (state == Cipher.ENCRYPT_MODE ? "SM9 encryption failed: " : "SM9 decryption failed: ") + e.getMessage(), e);
        }
        catch (IOException e)
        {
            throw SecurityExceptions.badPaddingException(failure(e), e);
        }
        catch (RuntimeException e)
        {
            // a crafted ciphertext can surface ArithmeticException / IllegalStateException /
            // ArrayIndexOutOfBoundsException from the ASN.1 / slicing layer; all are malformed input.
            throw SecurityExceptions.badPaddingException(failure(e), e);
        }
        finally
        {
            buffer.erase();
        }
    }

    /**
     * The message for a failure below the engine. On the decrypt path it is a malformed
     * ciphertext; on the encrypt path there is no ciphertext yet to be malformed - an IOException
     * there comes from writing the SM9Cipher structure - and saying otherwise sent a caller
     * looking at input it had not supplied.
     */
    private String failure(Exception e)
    {
        return (state == Cipher.ENCRYPT_MODE ? "SM9 encryption failed: " : "SM9 ciphertext malformed: ")
            + e.getMessage();
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        // The result's exact size is only known once the operation has run, so the check comes
        // after it - but the operation consumes the buffered input, and the JCA contract for
        // ShortBufferException is that this call can be repeated with a larger buffer. What
        // update() had buffered is therefore put back when the buffer turns out too short, leaving
        // the Cipher as it was before the call; the call's own input is not, as the repeated call
        // passes it again. A repeated encryption simply draws a fresh ephemeral.
        byte[] pending = buffer.toByteArray();
        try
        {
            byte[] result = engineDoFinal(input, inputOffset, inputLen);
            try
            {
                // outputOffset + result.length would overflow for an offset near Integer.MAX_VALUE,
                // which javax.crypto.Cipher passes on, as it refuses only a negative one
                if (outputOffset > output.length - result.length)
                {
                    buffer.write(pending, 0, pending.length);
                    throw new ShortBufferException("output buffer too short for SM9 result");
                }
                System.arraycopy(result, 0, output, outputOffset, result.length);
                return result.length;
            }
            finally
            {
                Arrays.clear(result);
            }
        }
        finally
        {
            Arrays.clear(pending);
        }
    }

    /**
     * A ByteArrayOutputStream whose contents can be zeroed: reset() only rewinds the count and
     * leaves what was written in the backing array, and a growth, left to ByteArrayOutputStream,
     * drops the array it replaces as it stands. GMCipherSpi carries the same class for its SM2 buffer.
     */
    private static final class ErasableOutputStream
        extends ByteArrayOutputStream
    {
        byte[] getBuf()
        {
            return buf;
        }

        void erase()
        {
            Arrays.fill(buf, (byte)0);
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

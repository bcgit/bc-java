package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.SM9Sm3;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.sm9.Fp12;
import org.bouncycastle.math.ec.sm9.SM9Curve;
import org.bouncycastle.math.ec.sm9.SM9Pairing;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The SM9 public key encryption algorithm (GM/T 0044.4-2016, clause 7). Two
 * data-encapsulation methods are supported: a KDF-based stream cipher
 * ({@link Mode#STREAM}) and SM4 in ECB mode with PKCS#7 padding
 * ({@link Mode#SM4}). The ciphertext is C = C1 || C3 || C2, where C1 is the
 * G1 point [r]Q_B encoded as x||y, C3 = MAC(K2, C2), and C2 is the encapsulated
 * message.
 * <p>
 * Usage follows the {@link SM2Engine} pattern: construct with the desired mode,
 * {@code init(true, new ParametersWithRandom(recipientKey, random))} to encrypt or
 * {@code init(false, userKey)} to decrypt, then {@link #processBlock(byte[], int, int)}.
 * <p>
 * The mode is the caller's to keep: C1 || C3 || C2 does not record which method produced it, so a
 * ciphertext has to be decrypted by an engine constructed for the mode it was encrypted in. Neither
 * mode produces or accepts a 16-byte C2: the stream mode refuses a 16-byte message, the SM4 mode a
 * message of fewer than 16 bytes, which pads to one block, and both refuse a 16-byte C2 on
 * decryption. A message of fewer than 16 bytes has to be sent in stream mode, and one of exactly
 * 16 bytes in SM4 mode.
 * <p>
 * <b>Usage warning:</b> an identity's encryption key should be used for this algorithm
 * or for the KEM ({@link org.bouncycastle.crypto.kems.SM9KEMExtractor}), but not for
 * both. A deployment needing both has its KGC publish a separate hid for each function,
 * as it already does for the key exchange, so that the two keys are distinct.
 */
public class SM9Engine
{
    /**
     * The GM/T 0044.4-2016 data-encapsulation method. (A constants class rather than
     * an enum so the single source also compiles for the legacy pre-Java-5
     * distributions.)
     */
    public static final class Mode
    {
        /** KDF-based stream cipher (XOR) encapsulation (method a). */
        public static final Mode STREAM = new Mode();
        /**
         * SM4/ECB/PKCS#7 block cipher encapsulation (method b), with no IV.
         * <p>
         * The three texts of the standard do not agree on what this method puts on the wire, and
         * the choice here is the one the Chinese edition's own worked example makes. GM/T 0044.4-2016
         * (Chinese) says only C2 = Enc(K1, M), naming no mode, IV or padding, and its companion
         * example, GM/T 0044.5-2016 Annex D.1, is SM4-ECB with PKCS#5 padding and no IV. The
         * official English translation adds a zero IV that is not transmitted and PKCS#7 padding,
         * and its Annex D.1 example is SM4-CBC. GB/T 38635.2-2020 9.2 places a 16-byte IV at the
         * front of C2 and allows any GB/T 17964 mode, and its example is CBC with a zero IV.
         * <p>
         * A peer built from the English edition or from GB/T 38635.2 therefore does not
         * interoperate with this mode. Agree the edition out of band.
         */
        public static final Mode SM4 = new Mode();

        private Mode()
        {
        }
    }

    private static final int K2_LEN = 32; // K2_len = 256 bits

    /**
     * Draws of r allowed for one encryption. A draw is discarded when it falls outside [1, N-1],
     * which a draw of N's bit length does with probability under 0.29, or when the derived K1 comes
     * out all zero, the standard's own retry, with probability 2^-(8 * K1_len). Needing this many
     * draws in a row has a probability below 2^-220, so reaching it means the random source is not
     * producing usable values rather than that the draws were unlucky.
     */
    private static final int MAX_REDRAWS = 128;

    /**
     * Largest K1 length the KDF can be asked for. In stream mode K1 is as long as the message, so
     * the KDF length (K1_len + K2_len) * 8 is driven by a caller- or wire-supplied size; past this
     * it overflows int and {@link SM9Sm3#kdf} sizes its output buffer from a negative length,
     * raising NegativeArraySizeException rather than the InvalidCipherTextException this engine
     * declares. The SM4 mode is unaffected - its K1 is a fixed 16 bytes.
     */
    private static final int MAX_K1_LEN = (Integer.MAX_VALUE / 8) - K2_LEN;

    /**
     * K1_len for the SM4 method: the SM4 key, 128 bits. It is also the one C2 length neither mode
     * produces or accepts: the stream mode refuses a 16-byte message and the SM4 mode a message of
     * fewer than 16 bytes, which pads to one block, and both refuse a 16-byte C2 on decryption. The
     * restriction covers both modes in both directions, and SM9EngineTest holds the engine to it.
     */
    private static final int SM4_K1_LEN = 16;

    private final Mode mode;

    private boolean forEncryption;
    private SM9EncPublicKeyParameters recipient;
    private SM9EncPrivateKeyParameters userKey;
    private SecureRandom random;

    /**
     * Base constructor: SM4 data encapsulation ({@link Mode#SM4}).
     */
    public SM9Engine()
    {
        this(Mode.SM4);
    }

    public SM9Engine(Mode mode)
    {
        if (mode == null)
        {
            throw new IllegalArgumentException("mode cannot be null");
        }
        this.mode = mode;
    }

    /**
     * Initialise the engine. For encryption pass the recipient's
     * {@link SM9EncPublicKeyParameters}, optionally wrapped in a
     * {@link ParametersWithRandom}; for decryption pass the user's
     * {@link SM9EncPrivateKeyParameters}. A recipient key formed under
     * {@link SM9EncMasterPrivateKeyParameters#HID_EXCHANGE}, or a key-exchange user key, is
     * refused: both belong to the key exchange, not to encryption.
     */
    public void init(boolean forEncryption, CipherParameters param)
    {
        // the previous key is dropped before the new parameters are examined, so that an init this
        // goes on to refuse leaves the engine uninitialised - processBlock then says so - rather than
        // still holding the last key for processBlock to run under
        this.recipient = null;
        this.userKey = null;
        this.random = null;
        this.forEncryption = forEncryption;

        if (forEncryption)
        {
            SecureRandom provided = null;
            CipherParameters key = param;
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;
                provided = rParam.getRandom();
                key = rParam.getParameters();
            }
            if (!(key instanceof SM9EncPublicKeyParameters))
            {
                throw new IllegalArgumentException("SM9 encryption requires an SM9EncPublicKeyParameters recipient key");
            }
            SM9EncPublicKeyParameters recipientKey = (SM9EncPublicKeyParameters)key;
            if (recipientKey.getHid() == SM9EncMasterPrivateKeyParameters.HID_EXCHANGE)
            {
                // the decryption side's refusal of a key-exchange key, made where the sender can see
                // it: no decryption key can be derived under the exchange's hid, so a ciphertext to
                // a recipient key formed under it could never be opened, and the mistake only
                // showed once the recipient tried
                throw new IllegalArgumentException(
                    "SM9 encryption requires an encryption recipient key, not a key-exchange key under HID_EXCHANGE (0x02)");
            }
            // the source is obtained before the recipient is installed, as the recipient is what
            // marks the engine initialised, and obtaining the default source can fail
            this.random = CryptoServicesRegistrar.getSecureRandom(provided);
            this.recipient = recipientKey;
        }
        else
        {
            if (!(param instanceof SM9EncPrivateKeyParameters))
            {
                throw new IllegalArgumentException("SM9 decryption requires an SM9EncPrivateKeyParameters user key");
            }
            SM9EncPrivateKeyParameters userKey = (SM9EncPrivateKeyParameters)param;
            if (userKey.isExchangeKey())
            {
                // keep the exchange and decryption usages on separate keys - a shared
                // key would give any exchange peer a pairing oracle on de
                throw new IllegalArgumentException(
                    "SM9 decryption requires an encryption user key, not a key-exchange key");
            }
            this.userKey = userKey;
            this.recipient = null;
            this.random = null;
        }
    }

    /**
     * Return an upper bound for the output produced by {@link #processBlock} on
     * {@code inputLen} input bytes (exact for encryption and stream-mode decryption,
     * an upper bound for SM4-mode decryption, whose padding length is unknown until
     * removed).
     */
    public int getOutputSize(int inputLen)
    {
        if (recipient == null && userKey == null)
        {
            // which direction the size is for depends on init, and forEncryption defaults to false,
            // so before it this silently answered as for decryption
            throw new IllegalStateException("SM9 engine not initialised");
        }
        if (inputLen < 0)
        {
            throw new IllegalArgumentException("inputLen cannot be negative");
        }
        if (forEncryption)
        {
            // in long arithmetic: the SM4 rounding and the 96-byte C1 || C3 overflow int near
            // Integer.MAX_VALUE, where the int form went negative
            long size = 96L + ((mode == Mode.SM4) ? ((((long)inputLen >> 4) + 1) << 4) : inputLen);
            if (size > Integer.MAX_VALUE)
            {
                throw new IllegalArgumentException("SM9 output for " + inputLen + " bytes does not fit an array");
            }
            return (int)size;
        }
        return Math.max(0, inputLen - 96);
    }

    public byte[] processBlock(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        if (inOff < 0 || inLen < 0 || inOff > in.length - inLen)
        {
            // the range is checked before it is copied, as SM2Engine checks it, rather than left to
            // surface as an ArrayIndexOutOfBoundsException from the copy
            throw new DataLengthException("input buffer too short");
        }
        byte[] data = new byte[inLen];
        System.arraycopy(in, inOff, data, 0, inLen);

        if (forEncryption)
        {
            if (recipient == null)
            {
                throw new IllegalStateException("SM9 engine not initialised for encryption");
            }
            try
            {
                return encrypt(data);
            }
            finally
            {
                // the copy is of the plaintext: Cipher.SM9 hands the message over in a buffer it
                // erases itself, and this copy is erased as well
                Arrays.clear(data);
            }
        }
        if (userKey == null)
        {
            throw new IllegalStateException("SM9 engine not initialised for decryption");
        }
        return decrypt(data);
    }

    private byte[] encrypt(byte[] message)
        throws InvalidCipherTextException
    {
        if (mode == Mode.STREAM && message.length == 0)
        {
            // K1_len is the message length, so an empty message has no K1 to test
            // against zero and the retry loop would never terminate; the SM4 mode
            // refuses it too, as it does every message of fewer than 16 bytes - see below.
            throw new InvalidCipherTextException("SM9 stream mode cannot encrypt an empty message");
        }

        SM9EncMasterPublicKeyParameters master = recipient.getMasterPublicKey();
        byte[] identity = recipient.getIdentity();
        Fp12 g = master.pairingWithP2();
        BigInteger n = SM9Curve.N;

        int k1Len = (mode == Mode.SM4) ? SM4_K1_LEN : message.length;
        if (k1Len > MAX_K1_LEN)
        {
            throw new InvalidCipherTextException("SM9 message too long for the stream mode KDF");
        }
        if (mode == Mode.STREAM && k1Len == SM4_K1_LEN)
        {
            // neither mode produces a 16-byte C2 - see SM4_K1_LEN
            throw new InvalidCipherTextException("SM9 stream mode cannot encrypt a 16-byte message");
        }
        if (mode == Mode.SM4 && message.length < SM4_K1_LEN)
        {
            // fewer than 16 bytes pad to a single SM4 block, a 16-byte C2 - see SM4_K1_LEN
            throw new InvalidCipherTextException("SM9 SM4 mode cannot encrypt a message shorter than 16 bytes");
        }
        if (mode == Mode.SM4 && 96L + ((((long)message.length >> 4) + 1) << 4) > Integer.MAX_VALUE)
        {
            // MAX_K1_LEN bounds the stream mode, whose K1 is as long as the message; the SM4 mode's
            // bound is the ciphertext's array, the test getOutputSize makes, where the padding's
            // length had overflowed int in the block cipher's output size
            throw new InvalidCipherTextException("SM9 message too long for an SM4-mode ciphertext to fit an array");
        }

        for (int attempt = 0; ; ++attempt)
        {
            if (attempt == MAX_REDRAWS)
            {
                // GM/T 0044.4 7.1.1 A6 redraws r on an all-zero K1 and does not bound the redraws,
                // because each is independent with probability 2^-(8 * K1_len). A source that yields
                // nothing usable - only zeros, say - would make the loop spin rather than fail, so it
                // is bounded: reaching this many draws is not a chance event.
                throw new InvalidCipherTextException("SM9 encryption could not draw a usable ephemeral");
            }
            // A1: r in [1, N-1], drawn and range-checked here rather than by
            // BigIntegers.createRandomInRange, which after a thousand draws out of range falls back
            // to one that cannot fail - for a source that yields only zeros, r = 1
            BigInteger r = BigIntegers.createRandomBigInteger(n.bitLength(), random);
            if (r.signum() == 0 || r.compareTo(n) >= 0)
            {
                continue;
            }
            // C1 = [r]Q_B, formed without forming Q_B - see multiplyRecipientPoint
            ECPoint c1;
            try
            {
                c1 = master.multiplyRecipientPoint(identity, recipient.getHid(), r);
            }
            catch (IllegalArgumentException e)
            {
                // Q_B at infinity: an identity the KGC could derive no user key for, so there is no
                // recipient to encrypt to. processBlock declares InvalidCipherTextException, and this
                // used to escape it as a NullPointerException from the pairing instead.
                throw new InvalidCipherTextException(e.getMessage());
            }
            Fp12 w = g.powSecureFixedBase(r);
            byte[] c1b = SM9Curve.g1ToBytes(c1);
            byte[] k = kdf(c1b, w, identity, (k1Len + K2_LEN) * 8);
            byte[] k1 = Arrays.copyOfRange(k, 0, k1Len);
            byte[] k2 = Arrays.copyOfRange(k, k1Len, k1Len + K2_LEN);
            try
            {
                if (Arrays.areAllZeroes(k1, 0, k1Len))
                {
                    continue;
                }
                byte[] c2 = (mode == Mode.SM4) ? sm4(true, k1, message) : xor(message, k1);
                byte[] c3 = mac(k2, c2);
                return Arrays.concatenate(c1b, c3, c2);
            }
            finally
            {
                // K1 is the SM4 key or the keystream and K2 the MAC key; none of them is needed
                // once the ciphertext is formed, or once the draw is discarded for an all-zero K1
                Arrays.clear(k);
                Arrays.clear(k1);
                Arrays.clear(k2);
            }
        }
    }

    private byte[] decrypt(byte[] ciphertext)
        throws InvalidCipherTextException
    {
        if (ciphertext.length < 64 + 32)
        {
            throw new InvalidCipherTextException("SM9 ciphertext too short");
        }
        if (mode == Mode.STREAM && ciphertext.length == 64 + 32)
        {
            throw new InvalidCipherTextException("SM9 stream-mode ciphertext has an empty C2");
        }
        if (mode == Mode.SM4 && (ciphertext.length == 64 + 32 || (ciphertext.length - (64 + 32)) % 16 != 0))
        {
            // SM4/ECB/PKCS#7 output is never empty and always whole blocks. Anything else would reach the
            // block cipher once the MAC checked - which the sender, knowing K2, can arrange - and fail there
            // with an unchecked DataLengthException; checked here it also costs no pairing.
            throw new InvalidCipherTextException("SM9 SM4-mode ciphertext has a C2 length that is not a positive multiple of 16");
        }
        ECPoint c1;
        try
        {
            c1 = SM9Curve.g1FromBytes(ciphertext, 0);
        }
        catch (IllegalArgumentException e)
        {
            // a coordinate at or above q is not a field element
            throw new InvalidCipherTextException("invalid SM9 ciphertext point C1", e);
        }
        if (c1.isInfinity() || !c1.isValid())
        {
            throw new InvalidCipherTextException("invalid SM9 ciphertext point C1");
        }
        byte[] c1b = SM9Curve.g1ToBytes(c1);
        byte[] c3 = Arrays.copyOfRange(ciphertext, 64, 96);
        byte[] c2 = Arrays.copyOfRange(ciphertext, 96, ciphertext.length);

        int k1Len = (mode == Mode.SM4) ? SM4_K1_LEN : c2.length;
        if (k1Len > MAX_K1_LEN)
        {
            // checked before the pairing so an over-long ciphertext is rejected without paying for one
            throw new InvalidCipherTextException("SM9 ciphertext too long for the stream mode KDF");
        }
        if (mode == Mode.STREAM && k1Len == SM4_K1_LEN)
        {
            // neither mode accepts a 16-byte C2 - see SM4_K1_LEN; refused before the pairing
            throw new InvalidCipherTextException("SM9 stream-mode ciphertext has a 16-byte C2");
        }
        if (mode == Mode.SM4 && c2.length == SM4_K1_LEN)
        {
            // likewise in this mode, which no longer produces one - see SM4_K1_LEN
            throw new InvalidCipherTextException("SM9 SM4-mode ciphertext has a 16-byte C2");
        }

        Fp12 w = SM9Pairing.pairing(c1, userKey.getPrivatePoint());
        byte[] k = kdf(c1b, w, userKey.getIdentity(), (k1Len + K2_LEN) * 8);
        byte[] k1 = Arrays.copyOfRange(k, 0, k1Len);
        byte[] k2 = Arrays.copyOfRange(k, k1Len, k1Len + K2_LEN);
        try
        {
            // B3's all-zero K1 and B5's MAC mismatch are both checked before either is acted on, and
            // a ciphertext either one refuses is refused in the same way: the refusal does not say
            // which check it failed
            boolean k1Zero = Arrays.areAllZeroes(k1, 0, k1Len);
            byte[] c3check = mac(k2, c2);
            boolean macFailed = !Arrays.constantTimeAreEqual(c3, c3check);
            // the MAC of C2 under K2 is erased once compared, as K2 is: for a C2 the caller chose it
            // is the C3 that would make that ciphertext pass the check
            Arrays.clear(c3check);
            if (k1Zero | macFailed)
            {
                throw new InvalidCipherTextException("SM9 MAC check failed");
            }
            return (mode == Mode.SM4) ? sm4(false, k1, c2) : xor(c2, k1);
        }
        finally
        {
            // however the decryption ends, the derived keys are not needed past it - and on the
            // rejection paths especially, K1 is the key to a ciphertext this call has refused
            Arrays.clear(k);
            Arrays.clear(k1);
            Arrays.clear(k2);
        }
    }

    /**
     * Run the KDF for one encryption or decryption. w is the secret K is derived from, so the array
     * it is serialised into and the KDF input built from it are erased once the KDF has read them,
     * as K, K1 and K2 are erased once they have been used.
     */
    private static byte[] kdf(byte[] c1b, Fp12 w, byte[] identity, int klenBits)
    {
        byte[] wb = SM9Pairing.toBytes(w);
        byte[] z = Arrays.concatenate(c1b, wb, identity);
        try
        {
            return SM9Sm3.kdf(z, klenBits);
        }
        finally
        {
            Arrays.clear(z);
            Arrays.clear(wb);
        }
    }

    private static byte[] xor(byte[] in, byte[] pad)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; ++i)
        {
            out[i] = (byte)(in[i] ^ pad[i]);
        }
        return out;
    }

    private static byte[] sm4(boolean forEncryption, byte[] key, byte[] in)
        throws InvalidCipherTextException
    {
        KeyParameter keyParam = new KeyParameter(key);
        byte[] out = null;
        byte[] result = null;
        try
        {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SM4Engine(), new PKCS7Padding());
            cipher.init(forEncryption, keyParam);
            out = new byte[cipher.getOutputSize(in.length)];
            int len = cipher.processBytes(in, 0, in.length, out, 0);
            len += cipher.doFinal(out, len);
            result = (len == out.length) ? out : Arrays.copyOfRange(out, 0, len);
            return result;
        }
        finally
        {
            // KeyParameter holds its own copy of K1, which erasing K1 does not reach. out is returned
            // as it is when nothing was stripped; otherwise - on decryption, or if the operation
            // failed - it is a working buffer holding the plaintext with its padding, and is erased
            Arrays.clear(keyParam.getKey());
            if (out != result)
            {
                Arrays.clear(out);
            }
        }
    }

    // MAC(K2, Z) = H_v(Z || K2) = SM3(Z || K2) (GM/T 0044.4) - note the key is hashed after the data.
    private static byte[] mac(byte[] k2, byte[] z)
    {
        SM3Digest sm3 = new SM3Digest();
        sm3.update(z, 0, z.length);
        sm3.update(k2, 0, k2.length);
        byte[] out = new byte[32];
        sm3.doFinal(out, 0);
        return out;
    }
}

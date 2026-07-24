package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.SM9Sm3;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPrivateKeyParameters;
import org.bouncycastle.crypto.params.SM9EncPublicKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
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
        /** SM4/ECB/PKCS#7 block cipher encapsulation (method b). */
        public static final Mode SM4 = new Mode();

        private Mode()
        {
        }
    }

    private static final int K2_LEN = 32; // K2_len = 256 bits

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
     * {@link SM9EncPrivateKeyParameters}.
     */
    public void init(boolean forEncryption, CipherParameters param)
    {
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
            this.recipient = (SM9EncPublicKeyParameters)key;
            this.userKey = null;
            this.random = CryptoServicesRegistrar.getSecureRandom(provided);
        }
        else
        {
            if (!(param instanceof SM9EncPrivateKeyParameters))
            {
                throw new IllegalArgumentException("SM9 decryption requires an SM9EncPrivateKeyParameters user key");
            }
            this.userKey = (SM9EncPrivateKeyParameters)param;
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
        if (forEncryption)
        {
            return 96 + ((mode == Mode.SM4) ? (((inputLen >> 4) + 1) << 4) : inputLen);
        }
        return Math.max(0, inputLen - 96);
    }

    public byte[] processBlock(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        byte[] data = new byte[inLen];
        System.arraycopy(in, inOff, data, 0, inLen);

        if (forEncryption)
        {
            if (recipient == null)
            {
                throw new IllegalStateException("SM9 engine not initialised for encryption");
            }
            return encrypt(data);
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
            // handles empty input (one padding block).
            throw new InvalidCipherTextException("SM9 stream mode cannot encrypt an empty message");
        }

        SM9EncMasterPublicKeyParameters master = recipient.getMasterPublicKey();
        byte[] id = recipient.getIdentity();
        ECPoint qb = master.recipientPoint(id);
        Fp12 g = master.pairingWithP2();
        BigInteger n = SM9Curve.N;

        int k1Len = (mode == Mode.SM4) ? 16 : message.length;

        for (;;)
        {
            BigInteger r = BigIntegers.createRandomInRange(ECConstants.ONE, n.subtract(ECConstants.ONE), random);
            ECPoint c1 = SM9Curve.multiplySecure(qb, r).normalize();
            Fp12 w = g.powSecure(r);
            byte[] c1b = SM9Curve.g1ToBytes(c1);
            byte[] k = SM9Sm3.kdf(Arrays.concatenate(c1b, SM9Pairing.toBytes(w), id), (k1Len + K2_LEN) * 8);
            byte[] k1 = Arrays.copyOfRange(k, 0, k1Len);
            if (Arrays.areAllZeroes(k1, 0, k1Len))
            {
                continue;
            }
            byte[] k2 = Arrays.copyOfRange(k, k1Len, k1Len + K2_LEN);
            byte[] c2 = (mode == Mode.SM4) ? sm4(true, k1, message) : xor(message, k1);
            byte[] c3 = mac(k2, c2);
            return Arrays.concatenate(c1b, c3, c2);
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
        ECPoint c1 = SM9Curve.g1FromBytes(ciphertext, 0);
        if (c1.isInfinity() || !c1.isValid())
        {
            throw new InvalidCipherTextException("invalid SM9 ciphertext point C1");
        }
        byte[] c1b = SM9Curve.g1ToBytes(c1);
        byte[] c3 = Arrays.copyOfRange(ciphertext, 64, 96);
        byte[] c2 = Arrays.copyOfRange(ciphertext, 96, ciphertext.length);

        Fp12 w = SM9Pairing.pairing(c1, userKey.getPrivatePoint());
        int k1Len = (mode == Mode.SM4) ? 16 : c2.length;
        byte[] k = SM9Sm3.kdf(Arrays.concatenate(c1b, SM9Pairing.toBytes(w), userKey.getIdentity()), (k1Len + K2_LEN) * 8);
        byte[] k1 = Arrays.copyOfRange(k, 0, k1Len);
        if (Arrays.areAllZeroes(k1, 0, k1Len))
        {
            throw new InvalidCipherTextException("SM9 key derivation produced all-zero K1");
        }
        byte[] k2 = Arrays.copyOfRange(k, k1Len, k1Len + K2_LEN);
        byte[] c3check = mac(k2, c2);
        if (!Arrays.constantTimeAreEqual(c3, c3check))
        {
            throw new InvalidCipherTextException("SM9 MAC check failed");
        }
        return (mode == Mode.SM4) ? sm4(false, k1, c2) : xor(c2, k1);
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
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SM4Engine(), new PKCS7Padding());
        cipher.init(forEncryption, new KeyParameter(key));
        byte[] out = new byte[cipher.getOutputSize(in.length)];
        int len = cipher.processBytes(in, 0, in.length, out, 0);
        len += cipher.doFinal(out, len);
        return (len == out.length) ? out : Arrays.copyOfRange(out, 0, len);
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

package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.SM9Sm3;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
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
 * ({@link #MODE_STREAM}) and SM4 in ECB mode with PKCS#7 padding
 * ({@link #MODE_SM4}). The ciphertext is C = C1 || C3 || C2, where C1 is the
 * G1 point [r]Q_B encoded as x||y, C3 = MAC(K2, C2), and C2 is the encapsulated
 * message.
 */
public class SM9Engine
{
    /** KDF-based stream cipher encapsulation (GM/T 0044.4-2016, method a). */
    public static final int MODE_STREAM = 0;
    /** SM4/ECB/PKCS#7 block cipher encapsulation (method b). */
    public static final int MODE_SM4 = 1;

    private static final int K2_LEN = 32; // K2_len = 256 bits

    public byte[] encrypt(int mode, SM9EncPublicKeyParameters recipient, byte[] message, SecureRandom random)
        throws InvalidCipherTextException
    {
        SM9EncMasterPublicKeyParameters master = recipient.getMasterPublicKey();
        byte[] id = recipient.getIdentity();
        ECPoint qb = master.recipientPoint(id);
        Fp12 g = master.pairingWithP2();
        SecureRandom rand = CryptoServicesRegistrar.getSecureRandom(random);
        BigInteger n = SM9Curve.N;

        int k1Len = (mode == MODE_SM4) ? 16 : message.length;

        for (;;)
        {
            BigInteger r = BigIntegers.createRandomInRange(ECConstants.ONE, n.subtract(ECConstants.ONE), rand);
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
            byte[] c2 = (mode == MODE_SM4) ? sm4(true, k1, message) : xor(message, k1);
            byte[] c3 = mac(k2, c2);
            return Arrays.concatenate(c1b, c3, c2);
        }
    }

    public byte[] decrypt(int mode, SM9EncPrivateKeyParameters key, byte[] ciphertext)
        throws InvalidCipherTextException
    {
        if (ciphertext.length < 64 + 32)
        {
            throw new InvalidCipherTextException("SM9 ciphertext too short");
        }
        ECPoint c1 = SM9Curve.g1FromBytes(ciphertext, 0);
        if (c1.isInfinity() || !c1.isValid())
        {
            throw new InvalidCipherTextException("invalid SM9 ciphertext point C1");
        }
        byte[] c1b = SM9Curve.g1ToBytes(c1);
        byte[] c3 = Arrays.copyOfRange(ciphertext, 64, 96);
        byte[] c2 = Arrays.copyOfRange(ciphertext, 96, ciphertext.length);

        Fp12 w = SM9Pairing.pairing(c1, key.getPrivatePoint());
        int k1Len = (mode == MODE_SM4) ? 16 : c2.length;
        byte[] k = SM9Sm3.kdf(Arrays.concatenate(c1b, SM9Pairing.toBytes(w), key.getIdentity()), (k1Len + K2_LEN) * 8);
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
        return (mode == MODE_SM4) ? sm4(false, k1, c2) : xor(c2, k1);
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

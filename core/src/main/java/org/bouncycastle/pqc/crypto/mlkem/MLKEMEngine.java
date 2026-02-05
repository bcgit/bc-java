package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

class MLKEMEngine
{
    private final MLKEMIndCpa indCpa;

    // constant parameters
    final static int N = 256;
    final static int Q = 3329;
    final static int Qinv = 62209;

    final static int SymBytes = 32; // Number of bytes for Hashes and Seeds
    final static int SharedSecretBytes = 32; // Number of Bytes for Shared Secret

    final static int PolyBytes = 384;

    final static int Eta2 = 2;

    final static int SeedBytes = SymBytes * 2;

    private final int K;
    private final int PolyVecBytes;
    private final int PolyCompressedBytes;
    private final int PolyVecCompressedBytes;
    private final int Eta1;
    private final int IndCpaPublicKeyBytes;
    private final int IndCpaSecretKeyBytes;
    private final int SecretKeyBytes;
    private final int CipherTextBytes;

    int getCipherTextBytes()
    {
        return CipherTextBytes;
    }

    int getSecretKeyBytes()
    {
        return SecretKeyBytes;
    }

    int getIndCpaPublicKeyBytes()
    {
        return IndCpaPublicKeyBytes;
    }

    int getIndCpaSecretKeyBytes()
    {
        return IndCpaSecretKeyBytes;
    }

    int getPublicKeyBytes()
    {
        return getIndCpaPublicKeyBytes();
    }

    int getPolyCompressedBytes()
    {
        return PolyCompressedBytes;
    }

    int getK()
    {
        return K;
    }

    int getPolyVecBytes()
    {
        return PolyVecBytes;
    }

    int getPolyVecCompressedBytes()
    {
        return PolyVecCompressedBytes;
    }

    int getEta1()
    {
        return Eta1;
    }

    MLKEMEngine(int k)
    {
        this.K = k;
        switch (k)
        {
        case 2:
            Eta1 = 3;
            PolyCompressedBytes = 128;
            PolyVecCompressedBytes = k * 320;
            break;
        case 3:
            Eta1 = 2;
            PolyCompressedBytes = 128;
            PolyVecCompressedBytes = k * 320;
            break;
        case 4:
            Eta1 = 2;
            PolyCompressedBytes = 160;
            PolyVecCompressedBytes = k * 352;
            break;
        default:
            throw new IllegalArgumentException("K: " + k + " is not supported for ML-KEM");
        }

        this.PolyVecBytes = k * PolyBytes;
        this.IndCpaPublicKeyBytes = PolyVecBytes + SymBytes;
        this.IndCpaSecretKeyBytes = PolyVecBytes;
        this.CipherTextBytes = PolyVecCompressedBytes + PolyCompressedBytes;
        this.SecretKeyBytes = IndCpaSecretKeyBytes + IndCpaPublicKeyBytes + 2 * SymBytes;

        this.indCpa = new MLKEMIndCpa(this);
    }

    boolean checkModulus(byte[] t)
    {
        return PolyVec.checkModulus(this, t) < 0;
    }

    boolean checkPrivateKey(byte[] encoding)
    {
        int k = getK(), k384 = k * 384, k768 = k * 768;

        if ((k768 + 96) != encoding.length)
        {
            throw new IllegalArgumentException("'encoding' has invalid length");
        }

        byte[] kH = new byte[SymBytes];
        hash_H(encoding, k384, k384 + 32, kH, 0);
        return Arrays.constantTimeAreEqual(SymBytes, kH, 0, encoding, k768 + 32);
    }

    public byte[][] generateKemKeyPair(SecureRandom random)
    {
        byte[] d = new byte[SymBytes];
        byte[] z = new byte[SymBytes];
        random.nextBytes(d);
        random.nextBytes(z);

        return generateKemKeyPairInternal(d, z);
    }

    //Internal functions are deterministic. No randomness is sampled inside them
    public byte[][] generateKemKeyPairInternal(byte[] d, byte[] z)
    {
        byte[][] indCpaKeyPair = indCpa.generateKeyPair(d);

        byte[] s = new byte[IndCpaSecretKeyBytes];

        System.arraycopy(indCpaKeyPair[1], 0, s, 0, IndCpaSecretKeyBytes);

        byte[] hashedPublicKey = new byte[32];

        hash_H(indCpaKeyPair[0], 0, indCpaKeyPair[0].length, hashedPublicKey, 0);

        byte[] outputPublicKey = new byte[IndCpaPublicKeyBytes];
        System.arraycopy(indCpaKeyPair[0], 0, outputPublicKey, 0, IndCpaPublicKeyBytes);
        return new byte[][]
        {
            Arrays.copyOfRange(outputPublicKey, 0, outputPublicKey.length - 32),
            Arrays.copyOfRange(outputPublicKey, outputPublicKey.length - 32, outputPublicKey.length),
            s,
            hashedPublicKey,
            z,
            Arrays.concatenate(d, z)
        };
    }

    static void hash_G(byte[] input, byte[] output)
    {
        implDigest(new SHA3Digest(512), input, 0, input.length, output, 0);
    }

    private static void hash_H(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
    {
        implDigest(new SHA3Digest(256), inBuf, inOff, inLen, outBuf, outOff);
    }

    private static void implDigest(SHA3Digest digest, byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
    {
        digest.update(inBuf, inOff, inLen);
        digest.doFinal(outBuf, outOff);
    }

    byte[][] kemEncrypt(MLKEMPublicKeyParameters publicKey, byte[] randBytes)
    {
        byte[] publicKeyInput = publicKey.getEncoded();

        byte[] buf = new byte[2 * SymBytes];
        byte[] kr = new byte[2 * SymBytes];

        System.arraycopy(randBytes, 0, buf, 0, SymBytes);

        // SHA3-256 Public Key
        hash_H(publicKeyInput, 0, publicKeyInput.length, buf, SymBytes);

        // SHA3-512( SHA3-256(RandBytes) || SHA3-256(PublicKey) )
        hash_G(buf, kr);

        // IndCpa Encryption
        byte[] outputCipherText = indCpa.encrypt(publicKeyInput, Arrays.copyOfRange(buf, 0, SymBytes),
            Arrays.copyOfRange(kr, 32, kr.length));

        byte[] outputSharedSecret = new byte[SharedSecretBytes];

        System.arraycopy(kr, 0, outputSharedSecret, 0, outputSharedSecret.length);

        byte[][] outBuf = new byte[2][];
        outBuf[0] = outputSharedSecret;
        outBuf[1] = outputCipherText;
        return outBuf;
    }

    byte[] kemDecrypt(MLKEMPrivateKeyParameters privateKey, byte[] cipherText)
    {
        byte[] secretKey = privateKey.getEncoded();

        byte[] buf = new byte[2 * SymBytes];
        indCpa.decrypt(secretKey, cipherText, buf);
        System.arraycopy(secretKey, SecretKeyBytes - 2 * SymBytes, buf, SymBytes, SymBytes);

        byte[] kr = new byte[2 * SymBytes];
        hash_G(buf, kr);

        byte[] publicKey = Arrays.copyOfRange(secretKey, IndCpaSecretKeyBytes, secretKey.length);

        byte[] cmp = indCpa.encrypt(publicKey, Arrays.copyOfRange(buf, 0, SymBytes),
            Arrays.copyOfRange(kr, SymBytes, kr.length));

        int fail = constantTimeZeroOnEqual(cipherText, cmp);

        // if ciphertexts do not match, “implicitly reject”
        {
            byte[] implicit_rejection = new byte[SharedSecretBytes];

            // J(z||c)
            SHAKEDigest xof = new SHAKEDigest(256);
            xof.update(secretKey, SecretKeyBytes - SymBytes, SymBytes);
            xof.update(cipherText, 0, CipherTextBytes);
            xof.doFinal(implicit_rejection, 0, SharedSecretBytes);

            cmov(kr, implicit_rejection, SharedSecretBytes, fail);
        }

        return Arrays.copyOfRange(kr, 0, SharedSecretBytes);
    }

    private void cmov(byte[] r, byte[] x, int xlen, int fail)
    {
        int mask = (0 - fail) >> 24;

        for (int i = 0; i != xlen; i++)
        {
            r[i] = (byte)((x[i] & mask) | (r[i] & ~mask));
        }
    }

    private int constantTimeZeroOnEqual(byte[] input, byte[] expected)
    {
        int result = expected.length ^ input.length;

        for (int i = 0; i != expected.length; i++)
        {
            result |= input[i] ^ expected[i];
        }

        return result & 0xff;
    }
}

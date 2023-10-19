package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.util.Arrays;

import java.security.SecureRandom;

class KyberEngine
{
    private SecureRandom random;
    private KyberIndCpa indCpa;

    // constant parameters
    public final static int KyberN = 256;
    public final static int KyberQ = 3329;
    public final static int KyberQinv = 62209;

    public final static int KyberSymBytes = 32; // Number of bytes for Hashes and Seeds
    private final static int KyberSharedSecretBytes = 32; // Number of Bytes for Shared Secret

    public final static int KyberPolyBytes = 384;

    private final static int KyberEta2 = 2;

    private final static int KyberIndCpaMsgBytes = KyberSymBytes;


    // parameters for Kyber{k}
    private final int KyberK;
    private final int KyberPolyVecBytes;
    private final int KyberPolyCompressedBytes;
    private final int KyberPolyVecCompressedBytes;
    private final int KyberEta1;
    private final int KyberIndCpaPublicKeyBytes;
    private final int KyberIndCpaSecretKeyBytes;
    private final int KyberIndCpaBytes;
    private final int KyberPublicKeyBytes;
    private final int KyberSecretKeyBytes;
    private final int KyberCipherTextBytes;

    // Crypto
    private final int CryptoBytes;
    private final int CryptoSecretKeyBytes;
    private final int CryptoPublicKeyBytes;
    private final int CryptoCipherTextBytes;

    private final int sessionKeyLength;
    private final Symmetric symmetric;

    public Symmetric getSymmetric()
    {
        return symmetric;
    }
    public static int getKyberEta2()
    {
        return KyberEta2;
    }

    public static int getKyberIndCpaMsgBytes()
    {
        return KyberIndCpaMsgBytes;
    }

    public int getCryptoCipherTextBytes()
    {
        return CryptoCipherTextBytes;
    }

    public int getCryptoPublicKeyBytes()
    {
        return CryptoPublicKeyBytes;
    }

    public int getCryptoSecretKeyBytes()
    {
        return CryptoSecretKeyBytes;
    }

    public int getCryptoBytes()
    {
        return CryptoBytes;
    }

    public int getKyberCipherTextBytes()
    {
        return KyberCipherTextBytes;
    }

    public int getKyberSecretKeyBytes()
    {
        return KyberSecretKeyBytes;
    }

    public int getKyberIndCpaPublicKeyBytes()
    {
        return KyberIndCpaPublicKeyBytes;
    }


    public int getKyberIndCpaSecretKeyBytes()
    {
        return KyberIndCpaSecretKeyBytes;
    }

    public int getKyberIndCpaBytes()
    {
        return KyberIndCpaBytes;
    }

    public int getKyberPublicKeyBytes()
    {
        return KyberPublicKeyBytes;
    }

    public int getKyberPolyCompressedBytes()
    {
        return KyberPolyCompressedBytes;
    }

    public int getKyberK()
    {
        return KyberK;
    }

    public int getKyberPolyVecBytes()
    {
        return KyberPolyVecBytes;
    }

    public int getKyberPolyVecCompressedBytes()
    {
        return KyberPolyVecCompressedBytes;
    }

    public int getKyberEta1()
    {
        return KyberEta1;
    }

    public KyberEngine(int k, boolean usingAes)
    {
        this.KyberK = k;
        switch (k)
        {
        case 2:
            KyberEta1 = 3;
            KyberPolyCompressedBytes = 128;
            KyberPolyVecCompressedBytes = k * 320;
            sessionKeyLength = 32;
            break;
        case 3:
            KyberEta1 = 2;
            KyberPolyCompressedBytes = 128;
            KyberPolyVecCompressedBytes = k * 320;
            sessionKeyLength = 32;
            break;
        case 4:
            KyberEta1 = 2;
            KyberPolyCompressedBytes = 160;
            KyberPolyVecCompressedBytes = k * 352;
            sessionKeyLength = 32;
            break;
        default:
            throw new IllegalArgumentException("K: " + k + " is not supported for Crystals Kyber");
        }

        this.KyberPolyVecBytes = k * KyberPolyBytes;
        this.KyberIndCpaPublicKeyBytes = KyberPolyVecBytes + KyberSymBytes;
        this.KyberIndCpaSecretKeyBytes = KyberPolyVecBytes;
        this.KyberIndCpaBytes = KyberPolyVecCompressedBytes + KyberPolyCompressedBytes;
        this.KyberPublicKeyBytes = KyberIndCpaPublicKeyBytes;
        this.KyberSecretKeyBytes = KyberIndCpaSecretKeyBytes + KyberIndCpaPublicKeyBytes + 2 * KyberSymBytes;
        this.KyberCipherTextBytes = KyberIndCpaBytes;

        // Define Crypto Params
        this.CryptoBytes = KyberSharedSecretBytes;
        this.CryptoSecretKeyBytes = KyberSecretKeyBytes;
        this.CryptoPublicKeyBytes = KyberPublicKeyBytes;
        this.CryptoCipherTextBytes = KyberCipherTextBytes;


        if(usingAes)
        {
            symmetric = new Symmetric.AesSymmetric();
        }
        else
        {
            symmetric = new Symmetric.ShakeSymmetric();
        }

        this.indCpa = new KyberIndCpa(this);
    }

    public void init(SecureRandom random)
    {
        this.random = random;
    }

    public byte[][] generateKemKeyPair()
    {
        byte[][] indCpaKeyPair = indCpa.generateKeyPair();

        byte[] s = new byte[KyberIndCpaSecretKeyBytes];

        System.arraycopy(indCpaKeyPair[1], 0, s, 0, KyberIndCpaSecretKeyBytes);

        byte[] hashedPublicKey = new byte[32];

        symmetric.hash_h(hashedPublicKey, indCpaKeyPair[0], 0);

        byte[] z = new byte[KyberSymBytes];
        random.nextBytes(z);

        byte[] outputPublicKey = new byte[KyberIndCpaPublicKeyBytes];
        System.arraycopy(indCpaKeyPair[0], 0, outputPublicKey, 0, KyberIndCpaPublicKeyBytes);
        return new byte[][]{ Arrays.copyOfRange(outputPublicKey, 0, outputPublicKey.length - 32), Arrays.copyOfRange(outputPublicKey, outputPublicKey.length - 32, outputPublicKey.length), s, hashedPublicKey, z };
    }

    public byte[][] kemEncrypt(byte[] publicKeyInput)
    {
        byte[] outputCipherText;

        byte[] buf = new byte[2 * KyberSymBytes];
        byte[] kr = new byte[2 * KyberSymBytes];

        byte[] randBytes = new byte[KyberSymBytes];

        random.nextBytes(randBytes);

        System.arraycopy(randBytes, 0, buf, 0, KyberSymBytes);

        // SHA3-256 Public Key
        symmetric.hash_h(buf, publicKeyInput, KyberSymBytes);

        // SHA3-512( SHA3-256(RandBytes) || SHA3-256(PublicKey) )
        symmetric.hash_g(kr, buf);

        // IndCpa Encryption
        outputCipherText = indCpa.encrypt(Arrays.copyOfRange(buf, 0, KyberSymBytes), publicKeyInput, Arrays.copyOfRange(kr, 32, kr.length));

        byte[] outputSharedSecret = new byte[sessionKeyLength];

        System.arraycopy(kr, 0, outputSharedSecret, 0, outputSharedSecret.length);
        
        byte[][] outBuf = new byte[2][];
        outBuf[0] = outputSharedSecret;
        outBuf[1] = outputCipherText;

        return outBuf;
    }

    public byte[] kemDecrypt(byte[] cipherText, byte[] secretKey)
    {
        byte[] buf = new byte[2 * KyberSymBytes],
            kr = new byte[2 * KyberSymBytes];

        byte[] publicKey = Arrays.copyOfRange(secretKey, KyberIndCpaSecretKeyBytes, secretKey.length);

        System.arraycopy(indCpa.decrypt(cipherText, secretKey), 0, buf, 0, KyberSymBytes);

        System.arraycopy(secretKey, KyberSecretKeyBytes - 2 * KyberSymBytes, buf, KyberSymBytes, KyberSymBytes);

        symmetric.hash_g(kr, buf);

        byte[] cmp = indCpa.encrypt(Arrays.copyOfRange(buf, 0, KyberSymBytes), publicKey, Arrays.copyOfRange(kr, KyberSymBytes, kr.length));

        boolean fail = !(Arrays.constantTimeAreEqual(cipherText, cmp));

        symmetric.hash_h(kr, cipherText, KyberSymBytes);

        cmov(kr, Arrays.copyOfRange(secretKey, KyberSecretKeyBytes - KyberSymBytes, KyberSecretKeyBytes), KyberSymBytes, fail);

        return Arrays.copyOfRange(kr, 0, sessionKeyLength);
    }

    private void cmov(byte[] r, byte[] x, int xlen, boolean b)
    {
        if (b)
        {
            System.arraycopy(x, 0, r, 0, xlen);
        }
        else
        {
            System.arraycopy(r, 0, r, 0, xlen);
        }
    }

    public void getRandomBytes(byte[] buf)
    {
        this.random.nextBytes(buf);
    }
}

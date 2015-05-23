package org.bouncycastle.openssl.jcajce;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class PEMUtilities
{
    private static final Map KEYSIZES = new HashMap();
    private static final Set PKCS5_SCHEME_1 = new HashSet();
    private static final Set PKCS5_SCHEME_2 = new HashSet();

    static
    {
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD2AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD2AndRC2_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD5AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithMD5AndRC2_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithSHA1AndDES_CBC);
        PKCS5_SCHEME_1.add(PKCSObjectIdentifiers.pbeWithSHA1AndRC2_CBC);

        PKCS5_SCHEME_2.add(PKCSObjectIdentifiers.id_PBES2);
        PKCS5_SCHEME_2.add(PKCSObjectIdentifiers.des_EDE3_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes128_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes192_CBC);
        PKCS5_SCHEME_2.add(NISTObjectIdentifiers.id_aes256_CBC);

        KEYSIZES.put(PKCSObjectIdentifiers.des_EDE3_CBC.getId(), Integers.valueOf(192));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes128_CBC.getId(), Integers.valueOf(128));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes192_CBC.getId(), Integers.valueOf(192));
        KEYSIZES.put(NISTObjectIdentifiers.id_aes256_CBC.getId(), Integers.valueOf(256));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC4.getId(), Integers.valueOf(128));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC4, Integers.valueOf(40));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd2_KeyTripleDES_CBC, Integers.valueOf(128));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, Integers.valueOf(192));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd128BitRC2_CBC, Integers.valueOf(128));
        KEYSIZES.put(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, Integers.valueOf(40));
    }

    static int getKeySize(String algorithm)
    {
        if (!KEYSIZES.containsKey(algorithm))
        {
            throw new IllegalStateException("no key size for algorithm: " + algorithm);
        }
        
        return ((Integer)KEYSIZES.get(algorithm)).intValue();
    }

    static boolean isPKCS5Scheme1(ASN1ObjectIdentifier algOid)
    {
        return PKCS5_SCHEME_1.contains(algOid);
    }

    static boolean isPKCS5Scheme2(ASN1ObjectIdentifier algOid)
    {
        return PKCS5_SCHEME_2.contains(algOid);
    }

    public static boolean isPKCS12(ASN1ObjectIdentifier algOid)
    {
        return algOid.getId().startsWith(PKCSObjectIdentifiers.pkcs_12PbeIds.getId());
    }

    public static SecretKey generateSecretKeyForPKCS5Scheme2(JcaJceHelper helper, String algorithm, char[] password, byte[] salt, int iterationCount)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory keyGen = helper.createSecretKeyFactory("PBKDF2with8BIT");

        SecretKey sKey = keyGen.generateSecret(new PBEKeySpec(password, salt, iterationCount, PEMUtilities.getKeySize(algorithm)));

        return new SecretKeySpec(sKey.getEncoded(), algorithm);
    }

    static byte[] crypt(
        boolean encrypt,
        JcaJceHelper helper,
        byte[]  bytes,
        char[]  password,
        String  dekAlgName,
        byte[]  iv)
        throws PEMException
    {
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        String                 alg;
        String                 blockMode = "CBC";
        String                 padding = "PKCS5Padding";
        Key                    sKey;

        // Figure out block mode and padding.
        if (dekAlgName.endsWith("-CFB"))
        {
            blockMode = "CFB";
            padding = "NoPadding";
        }
        if (dekAlgName.endsWith("-ECB") ||
            "DES-EDE".equals(dekAlgName) ||
            "DES-EDE3".equals(dekAlgName))
        {
            // ECB is actually the default (though seldom used) when OpenSSL
            // uses DES-EDE (des2) or DES-EDE3 (des3).
            blockMode = "ECB";
            paramSpec = null;
        }
        if (dekAlgName.endsWith("-OFB"))
        {
            blockMode = "OFB";
            padding = "NoPadding";
        }


        // Figure out algorithm and key size.
        if (dekAlgName.startsWith("DES-EDE"))
        {
            alg = "DESede";
            // "DES-EDE" is actually des2 in OpenSSL-speak!
            // "DES-EDE3" is des3.
            boolean des2 = !dekAlgName.startsWith("DES-EDE3");
            sKey = getKey(password, alg, 24, iv, des2);
        }
        else if (dekAlgName.startsWith("DES-"))
        {
            alg = "DES";
            sKey = getKey(password, alg, 8, iv);
        }
        else if (dekAlgName.startsWith("BF-"))
        {
            alg = "Blowfish";
            sKey = getKey(password, alg, 16, iv);
        }
        else if (dekAlgName.startsWith("RC2-"))
        {
            alg = "RC2";
            int keyBits = 128;
            if (dekAlgName.startsWith("RC2-40-"))
            {
                keyBits = 40;
            }
            else if (dekAlgName.startsWith("RC2-64-"))
            {
                keyBits = 64;
            }
            sKey = getKey(password, alg, keyBits / 8, iv);
            if (paramSpec == null) // ECB block mode
            {
                paramSpec = new RC2ParameterSpec(keyBits);
            }
            else
            {
                paramSpec = new RC2ParameterSpec(keyBits, iv);
            }
        }
        else if (dekAlgName.startsWith("AES-"))
        {
            alg = "AES";
            byte[] salt = iv;
            if (salt.length > 8)
            {
                salt = new byte[8];
                System.arraycopy(iv, 0, salt, 0, 8);
            }

            int keyBits;
            if (dekAlgName.startsWith("AES-128-"))
            {
                keyBits = 128;
            }
            else if (dekAlgName.startsWith("AES-192-"))
            {
                keyBits = 192;
            }
            else if (dekAlgName.startsWith("AES-256-"))
            {
                keyBits = 256;
            }
            else
            {
                throw new EncryptionException("unknown AES encryption with private key");
            }
            sKey = getKey(password, "AES", keyBits / 8, salt);
        }
        else
        {
            throw new EncryptionException("unknown encryption with private key");
        }

        String transformation = alg + "/" + blockMode + "/" + padding;

        try
        {
            Cipher c = helper.createCipher(transformation);
            int    mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

            if (paramSpec == null) // ECB block mode
            {
                c.init(mode, sKey);
            }
            else
            {
                c.init(mode, sKey, paramSpec);
            }
            return c.doFinal(bytes);
        }
        catch (Exception e)
        {
            throw new EncryptionException("exception using cipher - please check password and data.", e);
        }
    }

    private static SecretKey getKey(
        char[]  password,
        String  algorithm,
        int     keyLength,
        byte[]  salt)
    {
        return getKey(password, algorithm, keyLength, salt, false);
    }

    private static SecretKey getKey(
        char[]  password,
        String  algorithm,
        int     keyLength,
        byte[]  salt,
        boolean des2)
    {
        // TODO: need a secret key factory for this
        OpenSSLPBEParametersGenerator   pGen = new OpenSSLPBEParametersGenerator();

        pGen.init(Strings.toByteArray(password), salt);
        byte[] key = pGen.generateDerivedParameters(keyLength * 8);
        if (des2 && key.length >= 24)
        {
            // For DES2, we must copy first 8 bytes into the last 8 bytes.
            System.arraycopy(key, 0, key, 16, 8);
        }
        return new SecretKeySpec(key, algorithm);
    }

    private static abstract class GeneralDigest
    {
        private static final int BYTE_LENGTH = 64;

        private final byte[]  xBuf = new byte[4];
        private int           xBufOff;

        private long    byteCount;

        /**
         * Standard constructor
         */
        protected GeneralDigest()
        {
            xBufOff = 0;
        }

        /**
         * Copy constructor.  We are using copy constructors in place
         * of the Object.clone() interface as this interface is not
         * supported by J2ME.
         */
        protected GeneralDigest(GeneralDigest t)
        {
            copyIn(t);
        }

        protected GeneralDigest(byte[] encodedState)
        {
            System.arraycopy(encodedState, 0, xBuf, 0, xBuf.length);
            xBufOff = Pack.bigEndianToInt(encodedState, 4);
            byteCount = Pack.bigEndianToLong(encodedState, 8);
        }

        protected void copyIn(GeneralDigest t)
        {
            System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length);

            xBufOff = t.xBufOff;
            byteCount = t.byteCount;
        }

        public void update(
            byte in)
        {
            xBuf[xBufOff++] = in;

            if (xBufOff == xBuf.length)
            {
                processWord(xBuf, 0);
                xBufOff = 0;
            }

            byteCount++;
        }

        public void update(
            byte[]  in,
            int     inOff,
            int     len)
        {
            //
            // fill the current word
            //
            while ((xBufOff != 0) && (len > 0))
            {
                update(in[inOff]);

                inOff++;
                len--;
            }

            //
            // process whole words.
            //
            while (len > xBuf.length)
            {
                processWord(in, inOff);

                inOff += xBuf.length;
                len -= xBuf.length;
                byteCount += xBuf.length;
            }

            //
            // load in the remainder.
            //
            while (len > 0)
            {
                update(in[inOff]);

                inOff++;
                len--;
            }
        }

        public void finish()
        {
            long    bitLength = (byteCount << 3);

            //
            // add the pad bytes.
            //
            update((byte)128);

            while (xBufOff != 0)
            {
                update((byte)0);
            }

            processLength(bitLength);

            processBlock();
        }

        public void reset()
        {
            byteCount = 0;

            xBufOff = 0;
            for (int i = 0; i < xBuf.length; i++)
            {
                xBuf[i] = 0;
            }
        }

        protected void populateState(byte[] state)
        {
            System.arraycopy(xBuf, 0, state, 0, xBufOff);
            Pack.intToBigEndian(xBufOff, state, 4);
            Pack.longToBigEndian(byteCount, state, 8);
        }

        public int getByteLength()
        {
            return BYTE_LENGTH;
        }

        protected abstract void processWord(byte[] in, int inOff);

        protected abstract void processLength(long bitLength);

        protected abstract void processBlock();
    }

    static class MD5Digest
        extends GeneralDigest
    {
        private static final int    DIGEST_LENGTH = 16;

        private int     H1, H2, H3, H4;         // IV's

        private int[]   X = new int[16];
        private int     xOff;

        /**
         * Standard constructor
         */
        public MD5Digest()
        {
            reset();
        }

        /**
         * Copy constructor.  This will copy the state of the provided
         * message digest.
         */
        public MD5Digest(MD5Digest t)
        {
            super(t);

            copyIn(t);
        }

        private void copyIn(MD5Digest t)
        {
            super.copyIn(t);

            H1 = t.H1;
            H2 = t.H2;
            H3 = t.H3;
            H4 = t.H4;

            System.arraycopy(t.X, 0, X, 0, t.X.length);
            xOff = t.xOff;
        }

        public String getAlgorithmName()
        {
            return "MD5";
        }

        public int getDigestSize()
        {
            return DIGEST_LENGTH;
        }

        protected void processWord(
            byte[]  in,
            int     inOff)
        {
            X[xOff++] = (in[inOff] & 0xff) | ((in[inOff + 1] & 0xff) << 8)
                | ((in[inOff + 2] & 0xff) << 16) | ((in[inOff + 3] & 0xff) << 24);

            if (xOff == 16)
            {
                processBlock();
            }
        }

        protected void processLength(
            long    bitLength)
        {
            if (xOff > 14)
            {
                processBlock();
            }

            X[14] = (int)(bitLength & 0xffffffff);
            X[15] = (int)(bitLength >>> 32);
        }

        private void unpackWord(
            int     word,
            byte[]  out,
            int     outOff)
        {
            out[outOff]     = (byte)word;
            out[outOff + 1] = (byte)(word >>> 8);
            out[outOff + 2] = (byte)(word >>> 16);
            out[outOff + 3] = (byte)(word >>> 24);
        }

        public int doFinal(
            byte[]  out,
            int     outOff)
        {
            finish();

            unpackWord(H1, out, outOff);
            unpackWord(H2, out, outOff + 4);
            unpackWord(H3, out, outOff + 8);
            unpackWord(H4, out, outOff + 12);

            reset();

            return DIGEST_LENGTH;
        }

        /**
         * reset the chaining variables to the IV values.
         */
        public void reset()
        {
            super.reset();

            H1 = 0x67452301;
            H2 = 0xefcdab89;
            H3 = 0x98badcfe;
            H4 = 0x10325476;

            xOff = 0;

            for (int i = 0; i != X.length; i++)
            {
                X[i] = 0;
            }
        }

        //
        // round 1 left rotates
        //
        private static final int S11 = 7;
        private static final int S12 = 12;
        private static final int S13 = 17;
        private static final int S14 = 22;

        //
        // round 2 left rotates
        //
        private static final int S21 = 5;
        private static final int S22 = 9;
        private static final int S23 = 14;
        private static final int S24 = 20;

        //
        // round 3 left rotates
        //
        private static final int S31 = 4;
        private static final int S32 = 11;
        private static final int S33 = 16;
        private static final int S34 = 23;

        //
        // round 4 left rotates
        //
        private static final int S41 = 6;
        private static final int S42 = 10;
        private static final int S43 = 15;
        private static final int S44 = 21;

        /*
         * rotate int x left n bits.
         */
        private int rotateLeft(
            int x,
            int n)
        {
            return (x << n) | (x >>> (32 - n));
        }

        /*
         * F, G, H and I are the basic MD5 functions.
         */
        private int F(
            int u,
            int v,
            int w)
        {
            return (u & v) | (~u & w);
        }

        private int G(
            int u,
            int v,
            int w)
        {
            return (u & w) | (v & ~w);
        }

        private int H(
            int u,
            int v,
            int w)
        {
            return u ^ v ^ w;
        }

        private int K(
            int u,
            int v,
            int w)
        {
            return v ^ (u | ~w);
        }

        protected void processBlock()
        {
            int a = H1;
            int b = H2;
            int c = H3;
            int d = H4;

            //
            // Round 1 - F cycle, 16 times.
            //
            a = rotateLeft(a + F(b, c, d) + X[ 0] + 0xd76aa478, S11) + b;
            d = rotateLeft(d + F(a, b, c) + X[ 1] + 0xe8c7b756, S12) + a;
            c = rotateLeft(c + F(d, a, b) + X[ 2] + 0x242070db, S13) + d;
            b = rotateLeft(b + F(c, d, a) + X[ 3] + 0xc1bdceee, S14) + c;
            a = rotateLeft(a + F(b, c, d) + X[ 4] + 0xf57c0faf, S11) + b;
            d = rotateLeft(d + F(a, b, c) + X[ 5] + 0x4787c62a, S12) + a;
            c = rotateLeft(c + F(d, a, b) + X[ 6] + 0xa8304613, S13) + d;
            b = rotateLeft(b + F(c, d, a) + X[ 7] + 0xfd469501, S14) + c;
            a = rotateLeft(a + F(b, c, d) + X[ 8] + 0x698098d8, S11) + b;
            d = rotateLeft(d + F(a, b, c) + X[ 9] + 0x8b44f7af, S12) + a;
            c = rotateLeft(c + F(d, a, b) + X[10] + 0xffff5bb1, S13) + d;
            b = rotateLeft(b + F(c, d, a) + X[11] + 0x895cd7be, S14) + c;
            a = rotateLeft(a + F(b, c, d) + X[12] + 0x6b901122, S11) + b;
            d = rotateLeft(d + F(a, b, c) + X[13] + 0xfd987193, S12) + a;
            c = rotateLeft(c + F(d, a, b) + X[14] + 0xa679438e, S13) + d;
            b = rotateLeft(b + F(c, d, a) + X[15] + 0x49b40821, S14) + c;

            //
            // Round 2 - G cycle, 16 times.
            //
            a = rotateLeft(a + G(b, c, d) + X[ 1] + 0xf61e2562, S21) + b;
            d = rotateLeft(d + G(a, b, c) + X[ 6] + 0xc040b340, S22) + a;
            c = rotateLeft(c + G(d, a, b) + X[11] + 0x265e5a51, S23) + d;
            b = rotateLeft(b + G(c, d, a) + X[ 0] + 0xe9b6c7aa, S24) + c;
            a = rotateLeft(a + G(b, c, d) + X[ 5] + 0xd62f105d, S21) + b;
            d = rotateLeft(d + G(a, b, c) + X[10] + 0x02441453, S22) + a;
            c = rotateLeft(c + G(d, a, b) + X[15] + 0xd8a1e681, S23) + d;
            b = rotateLeft(b + G(c, d, a) + X[ 4] + 0xe7d3fbc8, S24) + c;
            a = rotateLeft(a + G(b, c, d) + X[ 9] + 0x21e1cde6, S21) + b;
            d = rotateLeft(d + G(a, b, c) + X[14] + 0xc33707d6, S22) + a;
            c = rotateLeft(c + G(d, a, b) + X[ 3] + 0xf4d50d87, S23) + d;
            b = rotateLeft(b + G(c, d, a) + X[ 8] + 0x455a14ed, S24) + c;
            a = rotateLeft(a + G(b, c, d) + X[13] + 0xa9e3e905, S21) + b;
            d = rotateLeft(d + G(a, b, c) + X[ 2] + 0xfcefa3f8, S22) + a;
            c = rotateLeft(c + G(d, a, b) + X[ 7] + 0x676f02d9, S23) + d;
            b = rotateLeft(b + G(c, d, a) + X[12] + 0x8d2a4c8a, S24) + c;

            //
            // Round 3 - H cycle, 16 times.
            //
            a = rotateLeft(a + H(b, c, d) + X[ 5] + 0xfffa3942, S31) + b;
            d = rotateLeft(d + H(a, b, c) + X[ 8] + 0x8771f681, S32) + a;
            c = rotateLeft(c + H(d, a, b) + X[11] + 0x6d9d6122, S33) + d;
            b = rotateLeft(b + H(c, d, a) + X[14] + 0xfde5380c, S34) + c;
            a = rotateLeft(a + H(b, c, d) + X[ 1] + 0xa4beea44, S31) + b;
            d = rotateLeft(d + H(a, b, c) + X[ 4] + 0x4bdecfa9, S32) + a;
            c = rotateLeft(c + H(d, a, b) + X[ 7] + 0xf6bb4b60, S33) + d;
            b = rotateLeft(b + H(c, d, a) + X[10] + 0xbebfbc70, S34) + c;
            a = rotateLeft(a + H(b, c, d) + X[13] + 0x289b7ec6, S31) + b;
            d = rotateLeft(d + H(a, b, c) + X[ 0] + 0xeaa127fa, S32) + a;
            c = rotateLeft(c + H(d, a, b) + X[ 3] + 0xd4ef3085, S33) + d;
            b = rotateLeft(b + H(c, d, a) + X[ 6] + 0x04881d05, S34) + c;
            a = rotateLeft(a + H(b, c, d) + X[ 9] + 0xd9d4d039, S31) + b;
            d = rotateLeft(d + H(a, b, c) + X[12] + 0xe6db99e5, S32) + a;
            c = rotateLeft(c + H(d, a, b) + X[15] + 0x1fa27cf8, S33) + d;
            b = rotateLeft(b + H(c, d, a) + X[ 2] + 0xc4ac5665, S34) + c;

            //
            // Round 4 - K cycle, 16 times.
            //
            a = rotateLeft(a + K(b, c, d) + X[ 0] + 0xf4292244, S41) + b;
            d = rotateLeft(d + K(a, b, c) + X[ 7] + 0x432aff97, S42) + a;
            c = rotateLeft(c + K(d, a, b) + X[14] + 0xab9423a7, S43) + d;
            b = rotateLeft(b + K(c, d, a) + X[ 5] + 0xfc93a039, S44) + c;
            a = rotateLeft(a + K(b, c, d) + X[12] + 0x655b59c3, S41) + b;
            d = rotateLeft(d + K(a, b, c) + X[ 3] + 0x8f0ccc92, S42) + a;
            c = rotateLeft(c + K(d, a, b) + X[10] + 0xffeff47d, S43) + d;
            b = rotateLeft(b + K(c, d, a) + X[ 1] + 0x85845dd1, S44) + c;
            a = rotateLeft(a + K(b, c, d) + X[ 8] + 0x6fa87e4f, S41) + b;
            d = rotateLeft(d + K(a, b, c) + X[15] + 0xfe2ce6e0, S42) + a;
            c = rotateLeft(c + K(d, a, b) + X[ 6] + 0xa3014314, S43) + d;
            b = rotateLeft(b + K(c, d, a) + X[13] + 0x4e0811a1, S44) + c;
            a = rotateLeft(a + K(b, c, d) + X[ 4] + 0xf7537e82, S41) + b;
            d = rotateLeft(d + K(a, b, c) + X[11] + 0xbd3af235, S42) + a;
            c = rotateLeft(c + K(d, a, b) + X[ 2] + 0x2ad7d2bb, S43) + d;
            b = rotateLeft(b + K(c, d, a) + X[ 9] + 0xeb86d391, S44) + c;

            H1 += a;
            H2 += b;
            H3 += c;
            H4 += d;

            //
            // reset the offset and clean out the word buffer.
            //
            xOff = 0;
            for (int i = 0; i != X.length; i++)
            {
                X[i] = 0;
            }
        }
    }

    static class OpenSSLPBEParametersGenerator
    {
        private MD5Digest digest = new MD5Digest();

        protected byte[]  password;
        protected byte[]  salt;
        protected int     iterationCount;


        /**
         * initialise the PBE generator.
         *
         * @param password the password converted into bytes (see below).
         * @param salt the salt to be mixed with the password.
         * @param iterationCount the number of iterations the "mixing" function
         * is to be applied for.
         */
        public void init(
            byte[]  password,
            byte[]  salt,
            int     iterationCount)
        {
            this.password = password;
            this.salt = salt;
            this.iterationCount = iterationCount;
        }

        /**
         * Construct a OpenSSL Parameters generator.
         */
        public OpenSSLPBEParametersGenerator()
        {
        }

        /**
         * Initialise - note the iteration count for this algorithm is fixed at 1.
         *
         * @param password password to use.
         * @param salt salt to use.
         */
        public void init(
           byte[] password,
           byte[] salt)
        {
            init(password, salt, 1);
        }

        /**
         * the derived key function, the ith hash of the password and the salt.
         */
        private byte[] generateDerivedKey(
            int bytesNeeded)
        {
            byte[]  buf = new byte[digest.getDigestSize()];
            byte[]  key = new byte[bytesNeeded];
            int     offset = 0;

            for (;;)
            {
                digest.update(password, 0, password.length);
                digest.update(salt, 0, salt.length);

                digest.doFinal(buf, 0);

                int len = (bytesNeeded > buf.length) ? buf.length : bytesNeeded;
                System.arraycopy(buf, 0, key, offset, len);
                offset += len;

                // check if we need any more
                bytesNeeded -= len;
                if (bytesNeeded == 0)
                {
                    break;
                }

                // do another round
                digest.reset();
                digest.update(buf, 0, buf.length);
            }

            return key;
        }

        /**
         * Generate a key parameter derived from the password, salt, and iteration
         * count we are currently initialised with.
         *
         * @param keySize the size of the key we want (in bits)
         * @return a KeyParameter object.
         * @exception IllegalArgumentException if the key length larger than the base hash size.
         */
        public byte[] generateDerivedParameters(
            int keySize)
        {
            keySize = keySize / 8;

            byte[]  dKey = generateDerivedKey(keySize);

            return Arrays.copyOfRange(dKey, 0, keySize);
        }
    }

}

package org.bouncycastle.crypto.tls;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

public abstract class TlsRsaKeyExchange
{
    public static final int PRE_MASTER_SECRET_LENGTH = 48;

    private static final BigInteger ONE = BigInteger.valueOf(1);

    private TlsRsaKeyExchange()
    {
    }

    public static byte[] decryptPreMasterSecret(byte[] in, int inOff, int inLen, RSAKeyParameters privateKey,
        int protocolVersion, SecureRandom secureRandom)
    {
        if (in == null || inLen < 1 || inLen > getInputLimit(privateKey) || inOff < 0 || inOff > in.length - inLen)
        {
            throw new IllegalArgumentException("input not a valid EncryptedPreMasterSecret");
        }

        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be an RSA private key");
        }

        BigInteger modulus = privateKey.getModulus();
        int bitLength = modulus.bitLength();
        if (bitLength < 512)
        {
            throw new IllegalArgumentException("'privateKey' must be at least 512 bits");
        }

        int bitsOfSecurity = ConstraintUtils.bitsOfSecurityFor(modulus);
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSA", bitsOfSecurity, privateKey,
            CryptoServicePurpose.DECRYPTION));

        if ((protocolVersion & 0xFFFF) != protocolVersion)
        {
            throw new IllegalArgumentException("'protocolVersion' must be a 16 bit value");
        }

        secureRandom = CryptoServicesRegistrar.getSecureRandom(secureRandom);

        /*
         * Generate random bytes we can use as a Pre-Master-Secret if the decrypted value is invalid.
         */
        byte[] result = new byte[PRE_MASTER_SECRET_LENGTH];
        secureRandom.nextBytes(result);

        try
        {
            BigInteger input = convertInput(modulus, in, inOff, inLen);
            byte[] encoding = rsaBlinded(privateKey, input, secureRandom);

            int pkcs1Length = (bitLength - 1) / 8;
            int plainTextOffset = encoding.length - PRE_MASTER_SECRET_LENGTH;

            int badEncodingMask = checkPkcs1Encoding2(encoding, pkcs1Length, PRE_MASTER_SECRET_LENGTH);
            int badVersionMask = -((Pack.bigEndianToShort(encoding, plainTextOffset) ^ protocolVersion) & 0xFFFF) >> 31;
            int fallbackMask = badEncodingMask | badVersionMask;

            for (int i = 0; i < PRE_MASTER_SECRET_LENGTH; ++i)
            {
                result[i] = (byte)((result[i] & fallbackMask) | (encoding[plainTextOffset + i] & ~fallbackMask));
            }

            Arrays.fill(encoding, (byte)0);
        }
        catch (Exception e)
        {
            /*
             * Decryption should never throw an exception; return a random value instead.
             *
             * In any case, a TLS server MUST NOT generate an alert if processing an RSA-encrypted premaster
             * secret message fails, or the version number is not as expected. Instead, it MUST continue the
             * handshake with a randomly generated premaster secret.
             */
        }

        return result;
    }

    public static int getInputLimit(RSAKeyParameters privateKey)
    {
        return (privateKey.getModulus().bitLength() + 7) / 8;
    }

    private static int caddTo(int len, int cond, byte[] x, byte[] z)
    {
//        assert cond == 0 || cond == -1;
        int mask = cond & 0xFF;

        int c = 0;
        for (int i = len - 1; i >= 0; --i)
        {
            c += (z[i] & 0xFF) + (x[i] & mask);
            z[i] = (byte)c;
            c >>>= 8;
        }
        return c;
    }

    /**
     * Check the argument is a valid encoding with type 2 of a plaintext with the given length. Returns 0 if
     * valid, or -1 if invalid.
     */
    private static int checkPkcs1Encoding2(byte[] buf, int pkcs1Length, int plaintextLength)
    {
        // The header should be at least 10 bytes
        int errorSign = pkcs1Length - plaintextLength - 10;

        int firstPadPos = buf.length - pkcs1Length;
        int lastPadPos = buf.length - 1 - plaintextLength;

        // Any leading bytes should be zero
        for (int i = 0; i < firstPadPos; ++i)
        {
            errorSign |= -(buf[i] & 0xFF);
        }

        // The first byte should be 0x02
        errorSign |= -((buf[firstPadPos] & 0xFF) ^ 0x02);

        // All pad bytes before the last one should be non-zero
        for (int i = firstPadPos + 1; i < lastPadPos; ++i)
        {
            errorSign |= (buf[i] & 0xFF) - 1;
        }

        // Last pad byte should be zero
        errorSign |= -(buf[lastPadPos] & 0xFF);

        return errorSign >> 31;
    }

    private static BigInteger convertInput(BigInteger modulus, byte[] in, int inOff, int inLen)
    {
        BigInteger result = BigIntegers.fromUnsignedByteArray(in, inOff, inLen);
        if (result.compareTo(modulus) < 0)
        {
            return result;
        }

        throw new DataLengthException("input too large for RSA cipher.");
    }

    private static BigInteger rsa(RSAKeyParameters privateKey, BigInteger input)
    {
        return input.modPow(privateKey.getExponent(), privateKey.getModulus());
    }

    private static byte[] rsaBlinded(RSAKeyParameters privateKey, BigInteger input, SecureRandom secureRandom)
    {
        BigInteger modulus = privateKey.getModulus();
        int resultSize = modulus.bitLength() / 8 + 1;

        if (privateKey instanceof RSAPrivateCrtKeyParameters)
        {
            RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters)privateKey;

            BigInteger e = crtKey.getPublicExponent();
            if (e != null)   // can't do blinding without a public exponent
            {
                BigInteger r = BigIntegers.createRandomInRange(ONE, modulus.subtract(ONE), secureRandom);
                BigInteger blind = r.modPow(e, modulus);
                BigInteger unblind = BigIntegers.modOddInverse(modulus, r);

                BigInteger blindedInput = blind.multiply(input).mod(modulus);
                BigInteger blindedResult = rsaCrt(crtKey, blindedInput);
                BigInteger offsetResult = unblind.add(ONE).multiply(blindedResult).mod(modulus);

                /*
                 * BigInteger conversion time is not constant, but is only done for blinded or public values.
                 */
                byte[] blindedResultBytes = toBytes(blindedResult, resultSize);
                byte[] modulusBytes = toBytes(modulus, resultSize);
                byte[] resultBytes = toBytes(offsetResult, resultSize);

                /*
                 * A final modular subtraction is done without timing dependencies on the final result. 
                 */
                int carry = subFrom(resultSize, blindedResultBytes, resultBytes);
                caddTo(resultSize, carry, modulusBytes, resultBytes);

                return resultBytes;
            }
        }

        return toBytes(rsa(privateKey, input), resultSize);
    }

    private static BigInteger rsaCrt(RSAPrivateCrtKeyParameters crtKey, BigInteger input)
    {
        //
        // we have the extra factors, use the Chinese Remainder Theorem - the author
        // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
        // advice regarding the expression of this.
        //
        BigInteger e = crtKey.getPublicExponent();
//        assert e != null;

        BigInteger p = crtKey.getP();
        BigInteger q = crtKey.getQ();
        BigInteger dP = crtKey.getDP();
        BigInteger dQ = crtKey.getDQ();
        BigInteger qInv = crtKey.getQInv();

        BigInteger mP, mQ, h, m;

        // mP = ((input mod p) ^ dP)) mod p
        mP = (input.remainder(p)).modPow(dP, p);

        // mQ = ((input mod q) ^ dQ)) mod q
        mQ = (input.remainder(q)).modPow(dQ, q);

        // h = qInv * (mP - mQ) mod p
        h = mP.subtract(mQ);
        h = h.multiply(qInv);
        h = h.mod(p);               // mod (in Java) returns the positive residual

        // m = h * q + mQ
        m = h.multiply(q).add(mQ);

        // defence against Arjen Lenstra’s CRT attack
        BigInteger check = m.modPow(e, crtKey.getModulus()); 
        if (!check.equals(input))
        {
            throw new IllegalStateException("RSA engine faulty decryption/signing detected");
        }

        return m;
    }

    private static int subFrom(int len, byte[] x, byte[] z)
    {
        int c = 0;
        for (int i = len - 1; i >= 0; --i)
        {
            c += (z[i] & 0xFF) - (x[i] & 0xFF);
            z[i] = (byte)c;
            c >>= 8;
        }
        return c;
    }

    private static byte[] toBytes(BigInteger output, int fixedSize)
    {
        byte[] bytes = output.toByteArray();

        byte[] result = new byte[fixedSize];
        System.arraycopy(bytes, 0, result, result.length - bytes.length, bytes.length);
        return result;
    }
}

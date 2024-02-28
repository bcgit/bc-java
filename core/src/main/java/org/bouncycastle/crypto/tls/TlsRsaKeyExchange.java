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
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private TlsRsaKeyExchange()
    {
    }

    public static byte[] decryptPreMasterSecret(byte[] encryptedPreMasterSecret, RSAKeyParameters privateKey,
        int protocolVersion, SecureRandom secureRandom)
    {
        if (encryptedPreMasterSecret == null)
        {
            throw new NullPointerException("'encryptedPreMasterSecret' cannot be null");
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
         * Generate 48 random bytes we can use as a Pre-Master-Secret if the decrypted value is invalid.
         */
        byte[] result = new byte[48];
        secureRandom.nextBytes(result);

        try
        {
            int pkcs1Length = (bitLength - 1) / 8;
            int plainTextOffset = pkcs1Length - 48;

            BigInteger input = convertInput(modulus, encryptedPreMasterSecret);
            BigInteger output = rsaBlinded(privateKey, input, secureRandom);
            byte[] block = convertOutput(output);

            byte[] encoding = block;
            if (block.length != pkcs1Length)
            {
                encoding = new byte[pkcs1Length];
            }

            int badEncodingMask = checkPkcs1Encoding2(encoding, 48);
            int badVersionMask = -((Pack.bigEndianToShort(encoding, plainTextOffset) ^ protocolVersion) & 0xFFFF) >> 31;
            int fallbackMask = badEncodingMask | badVersionMask;

            for (int i = 0; i < 48; ++i)
            {
                result[i] = (byte)((result[i] & fallbackMask) | (encoding[plainTextOffset + i] & ~fallbackMask));
            }

            Arrays.fill(block, (byte)0);
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

    /**
     * Check the argument is a valid encoding with type 2 of a plaintext with the given length. Returns 0 if
     * valid, or -1 if invalid.
     */
    private static int checkPkcs1Encoding2(byte[] buf, int plaintextLength)
    {
        // The first byte should be 0x02
        int badPadSign = -((buf[0] & 0xFF) ^ 0x02);

        int lastPadPos = buf.length - 1 - plaintextLength;

        // The header should be at least 10 bytes
        badPadSign |= lastPadPos - 9;

        // All pad bytes before the last one should be non-zero
        for (int i = 1; i < lastPadPos; ++i)
        {
            badPadSign |= (buf[i] & 0xFF) - 1;
        }

        // Last pad byte should be zero
        badPadSign |= -(buf[lastPadPos] & 0xFF);

        return badPadSign >> 31;
    }

    public static BigInteger convertInput(BigInteger modulus, byte[] input)
    {
        int inputLimit = (modulus.bitLength() + 7) / 8;

        if (input.length <= inputLimit)
        {
            BigInteger result = new BigInteger(1, input);
            if (result.compareTo(modulus) < 0)
            {
                return result;
            }
        }

        throw new DataLengthException("input too large for RSA cipher.");
    }

    public static byte[] convertOutput(BigInteger result)
    {
        byte[] output = result.toByteArray();

        byte[] rv;
        if (output[0] == 0) // have ended up with an extra zero byte, copy down.
        {
            rv = new byte[output.length - 1];

            System.arraycopy(output, 1, rv, 0, rv.length);
        }
        else // maintain decryption time
        {
            rv = new byte[output.length];

            System.arraycopy(output, 0, rv, 0, rv.length);
        }

        Arrays.fill(output, (byte) 0);

        return rv;
    }

    private static BigInteger rsa(RSAKeyParameters privateKey, BigInteger input)
    {
        if (privateKey instanceof RSAPrivateCrtKeyParameters)
        {
            //
            // we have the extra factors, use the Chinese Remainder Theorem - the author
            // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
            // advice regarding the expression of this.
            //
            RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters)privateKey;

            BigInteger e = crtKey.getPublicExponent();
            if (e != null)   // can't apply fault-attack countermeasure without public exponent
            {
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
        }

        return input.modPow(privateKey.getExponent(), privateKey.getModulus());
    }

    private static BigInteger rsaBlinded(RSAKeyParameters privateKey, BigInteger input, SecureRandom secureRandom)
    {
        if (privateKey instanceof RSAPrivateCrtKeyParameters)
        {
            RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters)privateKey;

            BigInteger e = crtKey.getPublicExponent();
            if (e != null)   // can't do blinding without a public exponent
            {
                BigInteger m = crtKey.getModulus();

                BigInteger r = BigIntegers.createRandomInRange(ONE, m.subtract(ONE), secureRandom);
                BigInteger blind = r.modPow(e, m);
                BigInteger unblind = BigIntegers.modOddInverse(m, r);

                BigInteger blindedInput = blind.multiply(input).mod(m);
                BigInteger blindedResult = rsa(privateKey, blindedInput);
                return unblind.multiply(blindedResult).mod(m);
            }
        }

        return rsa(privateKey, input);
    }
}

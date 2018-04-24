package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.BigIntegers;

class SRP6Util
{
    private static final byte[] colon = new byte[] { (byte)':' };

    private static BigInteger ZERO = BigInteger.valueOf(0);
    private static BigInteger ONE = BigInteger.valueOf(1);

    public static BigInteger calculateK(TlsHash digest, BigInteger N, BigInteger g)
    {
        return hashPaddedPair(digest, N, N, g);
    }

    public static BigInteger calculateU(TlsHash digest, BigInteger N, BigInteger A, BigInteger B)
    {
        return hashPaddedPair(digest, N, A, B);
    }

    public static BigInteger calculateX(TlsHash digest, BigInteger N, byte[] salt, byte[] identity, byte[] password)
    {
        digest.update(identity, 0, identity.length);
        digest.update(colon, 0, 1);
        digest.update(password, 0, password.length);

        byte[] output = digest.calculateHash();

        digest.update(salt, 0, salt.length);
        digest.update(output, 0, output.length);

        return new BigInteger(1, digest.calculateHash());
    }

    public static BigInteger generatePrivateValue(BigInteger N, BigInteger g, SecureRandom random)
    {
        int minBits = Math.min(256, N.bitLength() / 2);
        BigInteger min = ONE.shiftLeft(minBits - 1);
        BigInteger max = N.subtract(ONE);

        return BigIntegers.createRandomInRange(min, max, random);
    }

    public static BigInteger validatePublicValue(BigInteger N, BigInteger val)
        throws IllegalArgumentException
    {
        val = val.mod(N);

        // Check that val % N != 0
        if (val.equals(ZERO))
        {
            throw new IllegalArgumentException("Invalid public value: 0");
        }

        return val;
    }

    /** 
	 * Computes the client evidence message (M1) according to the standard routine:
	 * M1 = H( A | B | S )
	 * @param digest The Digest used as the hashing function H
	 * @param N Modulus used to get the pad length
	 * @param A The public client value
	 * @param B The public server value
	 * @param S The secret calculated by both sides
	 * @return M1 The calculated client evidence message
	 */
	public static BigInteger calculateM1(TlsHash digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S) {
		BigInteger M1 = hashPaddedTriplet(digest,N,A,B,S);
		return M1;
	}

	/** 
	 * Computes the server evidence message (M2) according to the standard routine:
	 * M2 = H( A | M1 | S )
	 * @param digest The Digest used as the hashing function H
	 * @param N Modulus used to get the pad length
	 * @param A The public client value
	 * @param M1 The client evidence message
	 * @param S The secret calculated by both sides
	 * @return M2 The calculated server evidence message
	 */
	public static BigInteger calculateM2(TlsHash digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S){
		BigInteger M2 = hashPaddedTriplet(digest,N,A,M1,S);
		return M2;
	}

	/**
	 * Computes the final Key according to the standard routine: Key = H(S)
	 * @param digest The Digest used as the hashing function H
	 * @param N Modulus used to get the pad length
	 * @param S The secret calculated by both sides
	 * @return the final Key value.
	 */
	public static BigInteger calculateKey(TlsHash digest, BigInteger N, BigInteger S) {
		int padLength = (N.bitLength() + 7) / 8;
		byte[] _S = getPadded(S,padLength);
		digest.update(_S, 0, _S.length);

        return new BigInteger(1, digest.calculateHash());
	}

	private static BigInteger hashPaddedTriplet(TlsHash digest, BigInteger N, BigInteger n1, BigInteger n2, BigInteger n3){
        int padLength = (N.bitLength() + 7) / 8;

        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);
        byte[] n3_bytes = getPadded(n3, padLength);

        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);
        digest.update(n3_bytes, 0, n3_bytes.length);

        return new BigInteger(1, digest.calculateHash());
    }

    private static BigInteger hashPaddedPair(TlsHash digest, BigInteger N, BigInteger n1, BigInteger n2)
    {
        int padLength = (N.bitLength() + 7) / 8;

        byte[] n1_bytes = getPadded(n1, padLength);
        byte[] n2_bytes = getPadded(n2, padLength);

        digest.update(n1_bytes, 0, n1_bytes.length);
        digest.update(n2_bytes, 0, n2_bytes.length);

        return new BigInteger(1, digest.calculateHash());
    }

    private static byte[] getPadded(BigInteger n, int length)
    {
        byte[] bs = BigIntegers.asUnsignedByteArray(n);
        if (bs.length < length)
        {
            byte[] tmp = new byte[length];
            System.arraycopy(bs, 0, tmp, length - bs.length, bs.length);
            bs = tmp;
        }
        return bs;
    }
}

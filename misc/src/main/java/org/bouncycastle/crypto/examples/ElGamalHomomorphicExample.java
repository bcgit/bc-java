package org.bouncycastle.crypto.examples;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Example: ElGamal is multiplicatively homomorphic, so the product of two
 * ciphertexts decrypts to the product of the two plaintexts &mdash; no library
 * change is needed, the property holds on BC's raw ciphertext bytes (github
 * issue #706).
 * <p>
 * Textbook ElGamal encrypts a message {@code m} under public key
 * {@code (p, g, y)} as the pair {@code (gamma, phi) = (g^k mod p, m*y^k mod p)}
 * for a fresh random {@code k}. Multiplying two ciphertexts component-wise mod
 * {@code p} gives
 * <pre>
 *   (gamma1*gamma2 mod p, phi1*phi2 mod p)
 *       = (g^(k1+k2), m1*m2*y^(k1+k2))
 *       = Enc(m1*m2)
 * </pre>
 * BC's {@code Cipher.getInstance("ElGamal/None/NoPadding", "BC")} emits exactly
 * this pair: the ciphertext is {@code 2*ceil(bitLength(p)/8)} bytes, two equal
 * halves, each the big-endian, left-zero-padded encoding of {@code gamma} and
 * {@code phi}. So the homomorphic product is obtained by splitting each
 * ciphertext in half, multiplying the halves mod {@code p}, and re-assembling
 * the same layout &mdash; see {@link #multiply}.
 * <p>
 * <b>Read this before using.</b>
 * <ul>
 * <li><b>The product must stay below {@code p}.</b> ElGamal recovers the product
 * <i>mod p</i>; for the small integers used here that is exactly the integer
 * product, but {@code m1*m2 >= p} would wrap.</li>
 * <li><b>Decryption strips leading zero bytes.</b> BC returns the plaintext as a
 * minimal-length unsigned byte array (e.g. {@code 33} comes back as a single
 * {@code 0x21} byte, not the four bytes a Java {@code int} would serialise to).
 * Compare on the recovered {@link BigInteger} <i>value</i>, as done here, rather
 * than on byte-array length.</li>
 * <li><b>This malleability is not a bug, and it is also why unpadded ElGamal is
 * not a general-purpose confidentiality scheme.</b> "ElGamal/None/NoPadding" is
 * textbook ElGamal: malleable and at best IND-CPA. The homomorphic property
 * demonstrated here <i>is</i> that malleability. Where you need
 * non-malleable / IND-CCA encryption and do not need the homomorphism, use a
 * padded / hybrid scheme (e.g. an IES construction) instead.</li>
 * </ul>
 * <p>
 * Run with {@code java -cp <bcprov-jar> org.bouncycastle.crypto.examples.ElGamalHomomorphicExample}.
 */
public class ElGamalHomomorphicExample
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        // Mirrors github issue #706: default 1024-bit ElGamal key pair, no explicit init.
        KeyPair keyPair = KeyPairGenerator.getInstance("ElGamal", "BC").generateKeyPair();
        PublicKey pub = keyPair.getPublic();
        PrivateKey priv = keyPair.getPrivate();

        // The prime modulus p the two ciphertext components live in. A BC ElGamal
        // public key is a DHPublicKey, so p is available without the deprecated
        // org.bouncycastle.jce.interfaces.ElGamalPublicKey type.
        BigInteger p = ((DHPublicKey)pub).getParams().getP();

        BigInteger a = BigInteger.valueOf(11);
        BigInteger b = BigInteger.valueOf(3);

        byte[] encA = encrypt(pub, a);
        byte[] encB = encrypt(pub, b);

        // Multiply the two ciphertexts WITHOUT decrypting them first.
        byte[] encProduct = multiply(encA, encB, p);

        BigInteger product = decrypt(priv, encProduct);

        System.out.println("a                  : " + a);
        System.out.println("b                  : " + b);
        System.out.println("Dec(Enc(a))        : " + decrypt(priv, encA));
        System.out.println("Dec(Enc(b))        : " + decrypt(priv, encB));
        System.out.println("Dec(Enc(a)*Enc(b)) : " + product);

        if (!product.equals(a.multiply(b)))
        {
            throw new IllegalStateException("homomorphic multiplication failed");
        }

        System.out.println("OK: ciphertext product decrypts to a*b = " + a.multiply(b));
    }

    private static byte[] encrypt(PublicKey pub, BigInteger value)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(value.toByteArray());
    }

    private static BigInteger decrypt(PrivateKey priv, byte[] ciphertext)
        throws Exception
    {
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return new BigInteger(1, cipher.doFinal(ciphertext));
    }

    /**
     * Multiply two ElGamal ciphertexts so the result decrypts to the product of
     * the underlying plaintexts. Each ciphertext is the concatenation
     * {@code gamma || phi} of two equal-length, left-zero-padded big-endian
     * components; the homomorphic product is {@code (gamma1*gamma2 mod p) ||
     * (phi1*phi2 mod p)} in the identical layout.
     */
    private static byte[] multiply(byte[] encA, byte[] encB, BigInteger p)
    {
        if (encA.length != encB.length)
        {
            throw new IllegalArgumentException("ciphertexts produced under different parameters");
        }

        int half = encA.length / 2;

        BigInteger gammaA = new BigInteger(1, Arrays.copyOfRange(encA, 0, half));
        BigInteger phiA = new BigInteger(1, Arrays.copyOfRange(encA, half, encA.length));
        BigInteger gammaB = new BigInteger(1, Arrays.copyOfRange(encB, 0, half));
        BigInteger phiB = new BigInteger(1, Arrays.copyOfRange(encB, half, encB.length));

        BigInteger gamma = gammaA.multiply(gammaB).mod(p);
        BigInteger phi = phiA.multiply(phiB).mod(p);

        byte[] output = new byte[encA.length];
        System.arraycopy(BigIntegers.asUnsignedByteArray(half, gamma), 0, output, 0, half);
        System.arraycopy(BigIntegers.asUnsignedByteArray(half, phi), 0, output, half, half);

        return output;
    }
}

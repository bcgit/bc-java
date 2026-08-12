package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Calculator for the EC based KDF algorithm described in RFC 6637
 */
public class RFC6637KDFCalculator
{
    // "Anonymous Sender    ", which is the octet sequence
    private static final byte[] ANONYMOUS_SENDER = Hex.decode("416E6F6E796D6F75732053656E64657220202020");

    private final PGPDigestCalculator digCalc;
    private final int keyAlgorithm;

    public RFC6637KDFCalculator(PGPDigestCalculator digCalc, int keyAlgorithm)
    {
        this.digCalc = digCalc;
        this.keyAlgorithm = keyAlgorithm;
    }

    public byte[] createKey(ECPoint s, byte[] userKeyingMaterial)
        throws PGPException
    {
        return createKey(s.getAffineXCoord().getEncoded(), userKeyingMaterial);
    }

    public byte[] createKey(byte[] secret, byte[] userKeyingMaterial)
        throws PGPException
    {
        try
        {
            // RFC 6637 - Section 8
            return KDF(digCalc, secret, getKeyLen(keyAlgorithm), userKeyingMaterial);
        }
        catch (IOException e)
        {
            throw new PGPException("Exception performing KDF: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a session key for X25519 or X448 encryption based on the provided algorithm and key algorithm.
     * <p>
     * The method follows the specifications outlined in the OpenPGP standards, specifically sections 5.1.6 and 5.1.7
     * of rfc9580.
     *
     * @param algorithm    The algorithm to use for key derivation, such as SHA256 or SHA512.
     * @param keyAlgorithm The key algorithm identifier, representing AES-128 or AES-256.
     * @param prepend      The bytes to prepend before deriving the key, which should include:
     *                     - 32/56 octets of the ephemeral X25519 or X448 public key
     *                     - 32/56 octets of the recipient public key material
     *                     - 32/56 octets of the shared secret
     * @param info         The info parameter used in the HKDF function. For X25519, use "OpenPGP X25519".
     *                     For X448, use "OpenPGP X448".
     * @return The derived key for encryption.
     * @throws PGPException If an error occurs during key derivation.
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html">rfc9580 - OpenPGP</a>
     */
    public static byte[] createKey(int algorithm, int keyAlgorithm, byte[] prepend, String info)
        throws PGPException
    {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(BcImplProvider.createDigest(algorithm));
        hkdf.init(new HKDFParameters(prepend, null, Strings.toByteArray(info)));
        byte[] key = new byte[getKeyLen(keyAlgorithm)];
        hkdf.generateBytes(key, 0, key.length);
        return key;
    }

    // RFC 6637 - Section 7
    //   Implements KDF( X, oBits, Param );
    //   Input: point X = (x,y)
    //   oBits - the desired size of output
    //   hBits - the size of output of hash function Hash
    //   Param - octets representing the parameters
    //   Assumes that oBits <= hBits
    //   Convert the point X to the octet string, see section 6:
    //   ZB' = 04 || x || y
    //   and extract the x portion from ZB'
    //         ZB = x;
    //         MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
    //   return oBits leftmost bits of MB.
    private static byte[] KDF(PGPDigestCalculator digCalc, byte[] ZB, int keyLen, byte[] param)
        throws IOException
    {
        OutputStream dOut = digCalc.getOutputStream();

        dOut.write(0x00);
        dOut.write(0x00);
        dOut.write(0x00);
        dOut.write(0x01);
        dOut.write(ZB);
        dOut.write(param);

        byte[] digest = digCalc.getDigest();

        byte[] key = new byte[keyLen];

        System.arraycopy(digest, 0, key, 0, key.length);

        return key;
    }

    private static int getKeyLen(int algID)
        throws PGPException
    {
        switch (algID)
        {
        case SymmetricKeyAlgorithmTags.AES_128:
        case SymmetricKeyAlgorithmTags.CAMELLIA_128:
            return 16;
        case SymmetricKeyAlgorithmTags.AES_192:
        case SymmetricKeyAlgorithmTags.CAMELLIA_192:
            return 24;
        case SymmetricKeyAlgorithmTags.AES_256:
        case SymmetricKeyAlgorithmTags.CAMELLIA_256:
            return 32;
        default:
            throw new PGPException("unknown symmetric algorithm ID: " + algID);
        }
    }
}

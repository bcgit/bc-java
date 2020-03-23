package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.encoders.Hex;

/**
 * Calculator for the EC based KDF algorithm described in RFC 6637
 */
class RFC6637KDFCalculator
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
            return 16;
        case SymmetricKeyAlgorithmTags.AES_192:
            return 24;
        case SymmetricKeyAlgorithmTags.AES_256:
            return 32;
        default:
            throw new PGPException("unknown symmetric algorithm ID: " + algID);
        }
    }
}

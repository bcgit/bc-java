package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Base class for an Edwards Curve (EdDSA) Secret Key.
 * This class is used with {@link PublicKeyAlgorithmTags#EDDSA_LEGACY} only and MUST NOT be used with v6 keys.
 * Modern OpenPGP uses dedicated key types:
 * For {@link PublicKeyAlgorithmTags#Ed25519} see {@link Ed25519SecretBCPGKey} instead.
 * For {@link PublicKeyAlgorithmTags#Ed448} see {@link Ed448SecretBCPGKey} instead.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ed">
 *     Crypto-Refresh - Algorithm-Specific Parts for EdDSALegacy Keys (deprecated)</a>
 */
public class EdSecretBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    MPInteger x;

    /**
     * @param in
     * @throws IOException
     */
    public EdSecretBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        this.x = new MPInteger(in);
    }

    /**
     * @param x
     */
    public EdSecretBCPGKey(
        BigInteger x)
    {
        this.x = new MPInteger(x);
    }

    /**
     * return "PGP"
     *
     * @see BCPGKey#getFormat()
     */
    public String getFormat()
    {
        return "PGP";
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see BCPGKey#getEncoded()
     */
    public byte[] getEncoded()
    {
        try
        {
            return super.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writeObject(x);
    }

    /**
     * @return x
     */
    public BigInteger getX()
    {
        return x.getValue();
    }
}

package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Base class for an EC Secret Key.
 * This type is for use with {@link PublicKeyAlgorithmTags#ECDH} or {@link PublicKeyAlgorithmTags#ECDSA}.
 * The specific curve is identified by providing an OID.
 * Regarding X25519, X448, consider the following:
 * ECDH keys using curve448 are unspecified.
 * ECDH secret keys using curve25519 use big-endian MPI encoding, contrary to {@link X25519SecretBCPGKey} which uses
 * native encoding.
 * Modern implementations use dedicated key types {@link X25519SecretBCPGKey}, {@link X448SecretBCPGKey} along with
 * dedicated algorithm tags {@link PublicKeyAlgorithmTags#X25519}, {@link PublicKeyAlgorithmTags#X448}.
 * If you want to be compatible with legacy applications however, you should use this class instead.
 * Note though, that for v6 keys, {@link X25519SecretBCPGKey} or {@link X448SecretBCPGKey} MUST be used for X25519, X448.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ecd">
 *     Crypto-Refresh - Algorithm-Specific Parts for ECDH Keys</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ec">
 *     Crypto-Refresh - Algorithm-Specific Parts for ECDSA Keys</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-curve25519legacy-ecdh-secre">
 *     Crypto-Refresh - Curve25519Legacy ECDH Secret Key Material (deprecated)</a>
 */
public class ECSecretBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    MPInteger x;

    /**
     * @param in
     * @throws IOException
     */
    public ECSecretBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        this.x = new MPInteger(in);
    }

    /**
     * @param x
     */
    public ECSecretBCPGKey(
        BigInteger x)
    {
        this.x = new MPInteger(x);
    }

    /**
     * return "PGP"
     *
     * @see org.bouncycastle.bcpg.BCPGKey#getFormat()
     */
    public String getFormat()
    {
        return "PGP";
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
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

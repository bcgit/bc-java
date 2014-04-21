package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;

/**
 * general class to contain a private key for use with other openPGP
 * objects.
 */
public class PGPPrivateKey
{
    private long          keyID;
    private PublicKeyPacket publicKeyPacket;
    private BCPGKey privateKeyDataPacket;

    /**
     * Base constructor.
     *
     * Create a PGPPrivateKey from a keyID and the associated public/private data packets needed
     * to fully describe it.
     *
     * @param keyID keyID associated with the public key.
     * @param publicKeyPacket the public key data packet to be associated with this private key.
     * @param privateKeyDataPacket the private key data packet to be associate with this private key.
     */
    public PGPPrivateKey(
        long keyID,
        PublicKeyPacket publicKeyPacket,
        BCPGKey privateKeyDataPacket)
    {
        this.keyID = keyID;
        this.publicKeyPacket = publicKeyPacket;
        this.privateKeyDataPacket = privateKeyDataPacket;
    }

    /**
     * Return the keyID associated with the contained private key.
     * 
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }

    /**
     * Return the public key packet associated with this private key, if available.
     *
     * @return associated public key packet, null otherwise.
     */
    public PublicKeyPacket getPublicKeyPacket()
    {
        return publicKeyPacket;
    }

    /**
     * Return the private key packet associated with this private key, if available.
     *
     * @return associated private key packet, null otherwise.
     */
    public BCPGKey getPrivateKeyDataPacket()
    {
        return privateKeyDataPacket;
    }
}

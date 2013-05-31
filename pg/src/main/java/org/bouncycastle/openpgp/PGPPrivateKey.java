package org.bouncycastle.openpgp;

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

/**
 * general class to contain a private key for use with other openPGP
 * objects.
 */
public class PGPPrivateKey
{
    private long          keyID;
    private PrivateKey    privateKey;
    private PublicKeyPacket publicKeyPacket;
    private BCPGKey privateKeyDataPacket;

    /**
     * Create a PGPPrivateKey from a regular private key and the keyID of its associated
     * public key.
     *
     * @param privateKey private key tu use.
     * @param keyID keyID of the corresponding public key.
     * @deprecated use JcaPGPKeyConverter
     */
    public PGPPrivateKey(
        PrivateKey        privateKey,
        long              keyID)
    {
        this.privateKey = privateKey;
        this.keyID = keyID;

        if (privateKey instanceof  RSAPrivateCrtKey)
        {
            RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privateKey;

            privateKeyDataPacket = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
        }
        else if (privateKey instanceof DSAPrivateKey)
        {
            DSAPrivateKey dsK = (DSAPrivateKey)privateKey;

            privateKeyDataPacket = new DSASecretBCPGKey(dsK.getX());
        }
        else if (privateKey instanceof  ElGamalPrivateKey)
        {
            ElGamalPrivateKey esK = (ElGamalPrivateKey)privateKey;

            privateKeyDataPacket = new ElGamalSecretBCPGKey(esK.getX());
        }
        else
        {
            throw new IllegalArgumentException("unknown key class");
        }

    }

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
     * Return the contained private key.
     * 
     * @return PrivateKey
     * @deprecated use a JcaPGPKeyConverter
     */
    public PrivateKey getKey()
    {
        if (privateKey != null)
        {
            return privateKey;
        }

        try
        {
            return new JcaPGPKeyConverter().setProvider(PGPUtil.getDefaultProvider()).getPrivateKey(this);
        }
        catch (PGPException e)
        {
            throw new IllegalStateException("unable to convert key: " + e.toString());
        }
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

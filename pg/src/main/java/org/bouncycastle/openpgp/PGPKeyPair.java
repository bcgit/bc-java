package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

/**
 * Class to hold an unlocked PGP key pair.
 * Note: the private key might be null, e.g. for PGP keys with external/removed private key material.
 */
public class PGPKeyPair
{
    protected PGPPublicKey pub;
    protected PGPPrivateKey priv; // might be null!

    /**
     * Create a key pair from a PGPPrivateKey and a PGPPublicKey.
     *
     * @param pub  the public key
     * @param priv the private key
     */
    public PGPKeyPair(
        PGPPublicKey pub,
        PGPPrivateKey priv)
    {
        this.pub = pub;
        this.priv = priv;
    }

    protected PGPKeyPair()
    {
    }

    /**
     * Return the keyID associated with this key pair.
     *
     * @return keyID
     */
    public long getKeyID()
    {
        return pub.getKeyID();
    }

    /**
     * Return the {@link KeyIdentifier} associated with the public key.
     *
     * @return key identifier
     */
    public KeyIdentifier getKeyIdentifier()
    {
        return getPublicKey().getKeyIdentifier();
    }

    public PGPPublicKey getPublicKey()
    {
        return pub;
    }

    public PGPPrivateKey getPrivateKey()
    {
        return priv;
    }

    /**
     * Return this PGP key pair as a subkey pair.
     * The public and private key packets get reconstructed into subkey packets.
     *
     * @param fingerPrintCalculator for fingerprint calculations
     * @return subkey pair
     * @throws PGPException if a subkey packet cannot be constructed properly
     */
    public PGPKeyPair asSubkey(KeyFingerPrintCalculator fingerPrintCalculator)
        throws PGPException
    {
        if (pub.getPublicKeyPacket() instanceof PublicSubkeyPacket)
        {
            return this; // is already subkey
        }

        // form subkey packet
        PublicSubkeyPacket pubSubPkt = new PublicSubkeyPacket(
            pub.getVersion(),
            pub.getAlgorithm(),
            pub.getCreationTime(),
            pub.getPublicKeyPacket().getKey());

        PGPPrivateKey privateKey = null;
        if (priv != null)
        {
            // reconstruct private key using public subkey packet
            privateKey = new PGPPrivateKey(pub.getKeyID(), pubSubPkt, priv.getPrivateKeyDataPacket());
        }

        return new PGPKeyPair(
            new PGPPublicKey(pubSubPkt, fingerPrintCalculator),
            privateKey);
    }
}

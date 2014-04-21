package org.bouncycastle.openpgp;

/**
 * General class to handle JCA key pairs and convert them into OpenPGP ones.
 * <p>
 * A word for the unwary, the KeyID for a OpenPGP public key is calculated from
 * a hash that includes the time of creation, if you pass a different date to the 
 * constructor below with the same public private key pair the KeyID will not be the
 * same as for previous generations of the key, so ideally you only want to do 
 * this once.
 */
public class PGPKeyPair
{
    protected PGPPublicKey        pub;
    protected PGPPrivateKey       priv;

    /**
     * Create a key pair from a PGPPrivateKey and a PGPPublicKey.
     * 
     * @param pub the public key
     * @param priv the private key
     */
    public PGPKeyPair(
        PGPPublicKey    pub,
        PGPPrivateKey   priv)
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
    
    public PGPPublicKey getPublicKey()
    {
        return pub;
    }
    
    public PGPPrivateKey getPrivateKey()
    {
        return priv;
    }
}

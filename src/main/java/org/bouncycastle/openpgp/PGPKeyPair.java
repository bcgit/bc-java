package org.bouncycastle.openpgp;

import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;


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
     * @deprecated use BcPGPKeyPair or JcaPGPKeyPair as appropriate.
     */
    public PGPKeyPair(
        int             algorithm,
        KeyPair         keyPair,
        Date            time,
        String          provider)
        throws PGPException, NoSuchProviderException
    {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate(), time, provider);
    }

    /**
     * @deprecated use BcPGPKeyPair or JcaPGPKeyPair as appropriate.
     */
    public PGPKeyPair(
        int             algorithm,
        KeyPair         keyPair,
        Date            time)
        throws PGPException
    {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate(), time);
    }

    /**
     * @deprecated use BcPGPKeyPair or JcaPGPKeyPair as appropriate.
     */
    public PGPKeyPair(
        int             algorithm,
        PublicKey       pubKey,
        PrivateKey      privKey,
        Date            time,
        String          provider)
        throws PGPException, NoSuchProviderException
    {
        this(algorithm, pubKey, privKey, time);
    }

    /**
     * @deprecated use BcPGPKeyPair or JcaPGPKeyPair as appropriate.
     */
    public PGPKeyPair(
        int             algorithm,
        PublicKey       pubKey,
        PrivateKey      privKey,
        Date            time)
        throws PGPException
    {
        this.pub = new PGPPublicKey(algorithm, pubKey, time);

        BCPGKey privPk;

        switch (pub.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_SIGN:
        case PGPPublicKey.RSA_GENERAL:
            RSAPrivateCrtKey rsK = (RSAPrivateCrtKey)privKey;

            privPk = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
            break;
        case PGPPublicKey.DSA:
            DSAPrivateKey dsK = (DSAPrivateKey)privKey;

            privPk = new DSASecretBCPGKey(dsK.getX());
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            ElGamalPrivateKey esK = (ElGamalPrivateKey)privKey;

            privPk = new ElGamalSecretBCPGKey(esK.getX());
            break;
        default:
            throw new PGPException("unknown key class");
        }
        this.priv = new PGPPrivateKey(pub.getKeyID(), pub.getPublicKeyPacket(), privPk);
    }

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

package org.bouncycastle.openpgp.operator.jcajce;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

/**
 * A PGP key pair class that is constructed from JCA/JCE key pairs.
 */
public class JcaPGPKeyPair
    extends PGPKeyPair
{
    @Deprecated
    private static PGPPublicKey getPublicKey(int algorithm, PublicKey pubKey, Date date)
        throws PGPException
    {
        return getPublicKey(PublicKeyPacket.VERSION_4, algorithm, pubKey, date);
    }

    private static PGPPublicKey getPublicKey(int version, int algorithm, PublicKey pubKey, Date date)
            throws PGPException
    {
        return new JcaPGPKeyConverter().getPGPPublicKey(version, algorithm, pubKey, date);
    }

    @Deprecated
    private static PGPPublicKey getPublicKey(int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date date)
        throws PGPException
    {
        return getPublicKey(PublicKeyPacket.VERSION_4, algorithm, algorithmParameters, pubKey, date);
    }

    private static PGPPublicKey getPublicKey(int version, int algorithm, PGPAlgorithmParameters algorithmParameters, PublicKey pubKey, Date date)
        throws PGPException
    {
        return new JcaPGPKeyConverter().getPGPPublicKey(version, algorithm, algorithmParameters, pubKey, date);
    }

    private static PGPPrivateKey getPrivateKey(PGPPublicKey pub, PrivateKey privKey)
        throws PGPException
    {
        return new JcaPGPKeyConverter().getPGPPrivateKey(pub, privKey);
    }

    /**
     * Construct PGP key pair from a JCA/JCE key pair.
     *
     * @param algorithm the PGP algorithm the key is for.
     * @param keyPair  the public/private key pair to convert.
     * @param date the creation date to associate with the key pair.
     * @throws PGPException if conversion fails.
     */
    @Deprecated
    public JcaPGPKeyPair(int algorithm, KeyPair keyPair, Date date)
        throws PGPException
    {
        this(PublicKeyPacket.VERSION_4, algorithm, keyPair, date);
    }

    public JcaPGPKeyPair(int version, int algorithm, KeyPair keyPair, Date date)
        throws PGPException
    {
        this.pub = getPublicKey(version, algorithm, keyPair.getPublic(), date);
        this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
    }

    /**
     * Construct version 4 PGP key pair from a JCA/JCE key pair.
     *
     * @param algorithm the PGP algorithm the key is for.
     * @param parameters additional parameters to be stored against the public key.
     * @param keyPair  the public/private key pair to convert.
     * @param date the creation date to associate with the key pair.
     * @throws PGPException if conversion fails.
     * @deprecated use versioned {@link #JcaPGPKeyPair(int, int, PGPAlgorithmParameters, KeyPair, Date)} instead
     */
    @Deprecated
    public JcaPGPKeyPair(int algorithm, PGPAlgorithmParameters parameters, KeyPair keyPair, Date date)
        throws PGPException
    {
        this(PublicKeyPacket.VERSION_4, algorithm, parameters, keyPair, date);
    }

    /**
     * Construct PGP key pair from a JCA/JCE key pair.
     *
     * @param version key version
     * @param algorithm the PGP algorithm the key is for.
     * @param parameters additional parameters to be stored against the public key.
     * @param keyPair  the public/private key pair to convert.
     * @param date the creation date to associate with the key pair.
     * @throws PGPException if conversion fails.
     */
    public JcaPGPKeyPair(int version, int algorithm, PGPAlgorithmParameters parameters, KeyPair keyPair, Date date)
            throws PGPException
    {
        this.pub = getPublicKey(version, algorithm, parameters, keyPair.getPublic(), date);
        this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
    }
}

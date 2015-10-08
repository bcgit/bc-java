package org.bouncycastle.openpgp.operator.bc;

import java.util.Date;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

public class BcPGPKeyPair
    extends PGPKeyPair
{
    private static PGPPublicKey getPublicKey(int algorithm, PGPAlgorithmParameters parameters, AsymmetricKeyParameter pubKey, Date date)
        throws PGPException
    {
        return new BcPGPKeyConverter().getPGPPublicKey(algorithm, parameters, pubKey, date);
    }

    private static PGPPrivateKey getPrivateKey(PGPPublicKey pub, AsymmetricKeyParameter privKey)
        throws PGPException
    {
        return new BcPGPKeyConverter().getPGPPrivateKey(pub, privKey);
    }

    public BcPGPKeyPair(int algorithm, AsymmetricCipherKeyPair keyPair, Date date)
        throws PGPException
    {
        this.pub = getPublicKey(algorithm, null, keyPair.getPublic(), date);
        this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
    }

    public BcPGPKeyPair(int algorithm, PGPAlgorithmParameters parameters, AsymmetricCipherKeyPair keyPair, Date date)
        throws PGPException
    {
        this.pub = getPublicKey(algorithm, parameters, keyPair.getPublic(), date);
        this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
    }
}

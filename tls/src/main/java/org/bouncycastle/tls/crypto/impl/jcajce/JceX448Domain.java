package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.util.Arrays;

public class JceX448Domain implements TlsECDomain
{
    protected final JcaTlsCrypto crypto;

    public JceX448Domain(JcaTlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    public JceTlsSecret calculateECDHAgreement(PrivateKey privateKey, PublicKey publicKey)
        throws IOException
    {
        try
        {
            byte[] secret = crypto.calculateKeyAgreement("X448", privateKey, publicKey, "TlsPremasterSecret");

            if (secret == null || secret.length != 56)
            {
                throw new TlsCryptoException("invalid secret calculated");
            }
            if (Arrays.areAllZeroes(secret, 0, secret.length))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            return crypto.adoptLocalSecret(secret);
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }

    public TlsAgreement createECDH()
    {
        return new JceX448(this);
    }

    public PublicKey decodePublicKey(byte[] encoding) throws IOException
    {
        return XDHUtil.decodePublicKey(crypto, "X448", EdECObjectIdentifiers.id_X448, encoding);
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException
    {
        return XDHUtil.encodePublicKey(publicKey);
    }

    public KeyPair generateKeyPair()
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("X448");
            keyPairGenerator.initialize(448, crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }
}

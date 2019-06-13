package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
        try
        {
            AlgorithmIdentifier algID = new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448);
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algID, encoding);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(spki.getEncoded(ASN1Encoding.DER));

            KeyFactory kf = crypto.getHelper().createKeyFactory("X448");
            return kf.generatePublic(keySpec);
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    public byte[] encodePublicKey(PublicKey publicKey) throws IOException
    {
        try
        {
            if ("X.509".equals(publicKey.getFormat()))
            {
                SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
                return spki.getPublicKeyData().getOctets();
            }
        }
        catch (Exception e)
        {
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
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

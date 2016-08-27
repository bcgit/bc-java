package org.bouncycastle.tls.crypto.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsAgreementCredentials;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.BigIntegers;

public class DefaultTlsAgreementCredentials
    implements TlsAgreementCredentials
{
    protected BcTlsCrypto crypto;
    protected Certificate certificate;
    protected AsymmetricKeyParameter privateKey;

    protected BasicAgreement basicAgreement;
    protected boolean truncateAgreement;

    public DefaultTlsAgreementCredentials(BcTlsCrypto crypto, Certificate certificate, AsymmetricKeyParameter privateKey)
    {
        if (crypto == null)
        {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null)
        {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty())
        {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (privateKey == null)
        {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!privateKey.isPrivate())
        {
            throw new IllegalArgumentException("'privateKey' must be private");
        }

        if (privateKey instanceof DHPrivateKeyParameters)
        {
            basicAgreement = new DHBasicAgreement();
            truncateAgreement = true;
        }
        else if (privateKey instanceof ECPrivateKeyParameters)
        {
            basicAgreement = new ECDHBasicAgreement();
            truncateAgreement = false;
        }
        else
        {
            throw new IllegalArgumentException("'privateKey' type not supported: "
                + privateKey.getClass().getName());
        }

        this.crypto = crypto;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public Certificate getCertificate()
    {
        return certificate;
    }

    public TlsSecret generateAgreement(TlsCertificate peerCertificate) throws IOException
    {
        TlsCertificate localCert = certificate.getCertificateAt(crypto.getContext(), 0);
        AsymmetricKeyParameter peerPublicKey = BcTlsCertificate.convert(crypto, localCert).getPublicKey();
        basicAgreement.init(privateKey);
        BigInteger agreementValue = basicAgreement.calculateAgreement(peerPublicKey);
        return crypto.adoptSecret(toByteArray(agreementValue));
    }

    protected byte[] toByteArray(BigInteger agreementValue)
    {
        if (truncateAgreement)
        {
            return BigIntegers.asUnsignedByteArray(agreementValue);
        }

        return BigIntegers.asUnsignedByteArray(basicAgreement.getFieldSize(), agreementValue);
    }
}

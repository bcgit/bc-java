package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS DH key exchange.
 */
public class TlsDHKeyExchange
    extends AbstractTlsKeyExchange
{
    protected TlsSigner tlsSigner;
    protected DHParameters dhParameters;

    protected AsymmetricKeyParameter serverPublicKey;
    protected TlsAgreementCredentials agreementCredentials;

    protected DHPrivateKeyParameters dhFixedAgreePrivateKey;
    protected DHPublicKeyParameters dhFixedAgreePublicKey;

    protected TlsDHConfig dhConfig;
    protected TlsAgreement agreement;

    public TlsDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters)
    {
        super(keyExchange, supportedSignatureAlgorithms);

        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DH_DSS:
            this.tlsSigner = null;
            break;
        case KeyExchangeAlgorithm.DHE_RSA:
            this.tlsSigner = new TlsRSASigner();
            break;
        case KeyExchangeAlgorithm.DHE_DSS:
            this.tlsSigner = new TlsDSSSigner();
            break;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.dhParameters = dhParameters;
    }

    public void init(TlsContext context)
    {
        super.init(context);

        if (this.tlsSigner != null)
        {
            this.tlsSigner.init(context);
        }
    }

    public void skipServerCredentials()
        throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        org.bouncycastle.asn1.x509.Certificate x509Cert = serverCertificate.getCertificateAt(0);

        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
        try
        {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }

        if (tlsSigner == null)
        {
            try
            {
                this.dhFixedAgreePublicKey = TlsDHUtils.validateDHPublicKey((DHPublicKeyParameters)this.serverPublicKey);
                this.dhParameters = validateDHParameters(dhFixedAgreePublicKey.getParameters());
            }
            catch (ClassCastException e)
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
            }

            TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyAgreement);
        }
        else
        {
            if (!tlsSigner.isValidPublicKey(this.serverPublicKey))
            {
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }

            TlsUtils.validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
        }

        super.processServerCertificate(serverCertificate);
    }

    public boolean requiresServerKeyExchange()
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return true;
        default:
            return false;
        }
    }

    public byte[] generateServerKeyExchange()
        throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            return null;
        }

        // DH_anon is handled here, DHE_* in a subclass

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        this.dhConfig = TlsDHUtils.selectDHConfig(dhParameters, buf);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        generateEphemeral(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input)
        throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        // DH_anon is handled here, DHE_* in a subclass

        this.dhConfig = TlsDHUtils.readDHConfig(input);

        byte[] y = TlsUtils.readOpaque16(input);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        processEphemeral(y);
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException
    {
        short[] types = certificateRequest.getCertificateTypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case ClientCertificateType.rsa_sign:
            case ClientCertificateType.dss_sign:
            case ClientCertificateType.rsa_fixed_dh:
            case ClientCertificateType.dss_fixed_dh:
            case ClientCertificateType.ecdsa_sign:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (clientCredentials instanceof TlsAgreementCredentials)
        {
            // TODO Validate client cert has matching parameters (see 'areCompatibleParameters')?

            this.agreementCredentials = (TlsAgreementCredentials)clientCredentials;
        }
        else if (clientCredentials instanceof TlsSignerCredentials)
        {
            // OK
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
        /*
         * RFC 2246 7.4.7.2 If the client certificate already contains a suitable Diffie-Hellman
         * key, then Yc is implicit and does not need to be sent again. In this case, the Client Key
         * Exchange message will be sent, but will be empty.
         */
        if (agreementCredentials == null)
        {
            generateEphemeral(output);
        }
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException
    {
        // TODO Extract the public key and validate

        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        // TODO Extract the public key and validate

        /*
         * TODO If the certificate is 'fixed', take the public key as dhFixedAgreePublicKey and check
         * that the parameters match the server's (see 'areCompatibleParameters').
         */
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        if (dhFixedAgreePublicKey != null)
        {
            // For dss_fixed_dh and rsa_fixed_dh, the key arrived in the client certificate
            return;
        }

        byte[] y = TlsUtils.readOpaque16(input);

        processEphemeral(y);
    }

    public byte[] generatePremasterSecret()
        throws IOException
    {
        if (agreementCredentials != null)
        {
            return agreementCredentials.generateAgreement(dhFixedAgreePublicKey);
        }

        if (agreement != null)
        {
            TlsSecret premasterSecret = agreement.calculateSecret();

            // TODO[tls-ops] Return as TlsSecret instead of exporting
            return premasterSecret.extract();
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void generateEphemeral(OutputStream output) throws IOException
    {
        byte[] y = agreement.generateEphemeral();
        TlsUtils.writeOpaque16(y, output);
    }

    protected int getMinimumPrimeBits()
    {
        return 1024;
    }

    protected void processEphemeral(byte[] y) throws IOException
    {
        this.agreement.receivePeerValue(y);
    }

    protected DHParameters validateDHParameters(DHParameters params) throws IOException
    {
        if (params.getP().bitLength() < getMinimumPrimeBits())
        {
            throw new TlsFatalAlert(AlertDescription.insufficient_security);
        }

        return TlsDHUtils.validateDHParameters(params);
    }
}

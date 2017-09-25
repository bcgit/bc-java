package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS DH key exchange.
 */
public class TlsDHKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_anon:
        case KeyExchangeAlgorithm.DH_DSS:
        case KeyExchangeAlgorithm.DH_RSA:
        case KeyExchangeAlgorithm.DHE_DSS:
        case KeyExchangeAlgorithm.DHE_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsDHConfigVerifier dhConfigVerifier;

    protected TlsCredentialedAgreement agreementCredentials;
    protected TlsCertificate dhPeerCertificate;

    protected TlsDHConfig dhConfig;
    protected TlsAgreement agreement;

    public TlsDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfigVerifier dhConfigVerifier)
    {
        this(keyExchange, supportedSignatureAlgorithms, dhConfigVerifier, null);
    }

    public TlsDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfig dhConfig)
    {
        this(keyExchange, supportedSignatureAlgorithms, null, dhConfig);
    }

    private TlsDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfigVerifier dhConfigVerifier,
        TlsDHConfig dhConfig)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.dhConfigVerifier = dhConfigVerifier;
        this.dhConfig = dhConfig;
    }

    public void skipServerCredentials() throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (!(serverCredentials instanceof TlsCredentialedAgreement))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.agreementCredentials = (TlsCredentialedAgreement)serverCredentials;
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        checkServerCertSigAlg(serverCertificate);

        this.dhPeerCertificate = validatePeerCertificate(ConnectionEnd.server, serverCertificate);
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

    public byte[] generateServerKeyExchange() throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            return null;
        }

        // DH_anon is handled here, DHE_* in a subclass

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        TlsDHUtils.writeDHConfig(dhConfig, buf);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        generateEphemeral(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        // DH_anon is handled here, DHE_* in a subclass

        this.dhConfig = TlsDHUtils.receiveDHConfig(dhConfigVerifier, input);

        byte[] y = TlsUtils.readOpaque16(input);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        processEphemeral(y);
    }

    public short[] getClientCertificateTypes()
    {
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            return null;
        }

        return new short[]{ ClientCertificateType.dss_fixed_dh, ClientCertificateType.rsa_fixed_dh };
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (clientCredentials instanceof TlsCredentialedAgreement)
        {
            this.agreementCredentials = (TlsCredentialedAgreement)clientCredentials;

            // TODO Check that the client certificate's domain parameters match the server's?
        }
        else
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
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
        if (keyExchange == KeyExchangeAlgorithm.DH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        if (agreementCredentials != null)
        {
            // TODO[tls-ops] Where to check that the domain parameters match the server's?
            this.dhPeerCertificate = validatePeerCertificate(ConnectionEnd.client, clientCertificate);
        }
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        if (dhPeerCertificate != null)
        {
            // For dss_fixed_dh and rsa_fixed_dh, the key arrived in the client certificate
            return;
        }

        byte[] y = TlsUtils.readOpaque16(input);

        processEphemeral(y);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        if (agreementCredentials != null)
        {
            return agreementCredentials.generateAgreement(dhPeerCertificate);
        }

        if (agreement != null)
        {
            return agreement.calculateSecret();
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void generateEphemeral(OutputStream output) throws IOException
    {
        byte[] y = agreement.generateEphemeral();
        TlsUtils.writeOpaque16(y, output);
    }

    protected void processEphemeral(byte[] y) throws IOException
    {
        this.agreement.receivePeerValue(y);
    }

    protected TlsCertificate validatePeerCertificate(int connectionEnd, Certificate peerCertificate) throws IOException
    {
        if (peerCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        return peerCertificate.getCertificateAt(0).useInRole(connectionEnd, keyExchange);
    }
}

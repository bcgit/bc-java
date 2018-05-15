package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS ECDH key exchange (see RFC 4492).
 */
public class TlsECDHKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.ECDH_ECDSA:
        case KeyExchangeAlgorithm.ECDH_RSA:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsECConfigVerifier ecConfigVerifier;
    protected short[] clientECPointFormats, serverECPointFormats;

    protected TlsCredentialedAgreement agreementCredentials;
    protected TlsCertificate ecdhPeerCertificate;

    protected TlsECConfig ecConfig;
    protected TlsAgreement agreement;

    public TlsECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats, short[] serverECPointFormats)
    {
        this(keyExchange, supportedSignatureAlgorithms, ecConfigVerifier, null, clientECPointFormats,
            serverECPointFormats);
    }

    public TlsECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsECConfig ecConfig,
        short[] serverECPointFormats)
    {
        this(keyExchange, supportedSignatureAlgorithms, null, ecConfig, null, serverECPointFormats);
    }

    private TlsECDHKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
        TlsECConfigVerifier ecConfigVerifier, TlsECConfig ecConfig, short[] clientECPointFormats,
        short[] serverECPointFormats)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.ecConfigVerifier = ecConfigVerifier;
        this.ecConfig = ecConfig;
        this.clientECPointFormats = clientECPointFormats;
        this.serverECPointFormats = serverECPointFormats;
    }

    public void skipServerCredentials() throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.ECDH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.ECDH_anon)
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
        if (keyExchange == KeyExchangeAlgorithm.ECDH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        checkServerCertSigAlg(serverCertificate);

        this.ecdhPeerCertificate = validatePeerCertificate(ConnectionEnd.server, serverCertificate);
    }

    public boolean requiresServerKeyExchange()
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.ECDH_anon:
        case KeyExchangeAlgorithm.ECDHE_ECDSA:
        case KeyExchangeAlgorithm.ECDHE_RSA:
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

        // ECDH_anon is handled here, ECDHE_* in a subclass

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        TlsECCUtils.writeECConfig(ecConfig, buf);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        generateEphemeral(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        if (!requiresServerKeyExchange())
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        // ECDH_anon is handled here, ECDHE_* in a subclass

        this.ecConfig = TlsECCUtils.receiveECConfig(ecConfigVerifier, serverECPointFormats, input);

        byte[] point = TlsUtils.readOpaque8(input);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        processEphemeral(clientECPointFormats, point);
    }

    public short[] getClientCertificateTypes()
    {
        if (keyExchange == KeyExchangeAlgorithm.ECDH_anon)
        {
            return null;
        }

        /*
         * RFC 4492 3. [...] The ECDSA_fixed_ECDH and RSA_fixed_ECDH mechanisms are usable with
         * ECDH_ECDSA and ECDH_RSA. Their use with ECDHE_ECDSA and ECDHE_RSA is prohibited because
         * the use of a long-term ECDH client key would jeopardize the forward secrecy property of
         * these algorithms.
         */
        return new short[]{ ClientCertificateType.ecdsa_fixed_ecdh, ClientCertificateType.rsa_fixed_ecdh };
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.ECDH_anon)
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
        if (agreementCredentials == null)
        {
            generateEphemeral(output);
        }
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.ECDH_anon)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        if (agreementCredentials != null)
        {
            // TODO[tls-ops] Where to check that the domain parameters match the server's?
            this.ecdhPeerCertificate = validatePeerCertificate(ConnectionEnd.client, clientCertificate);
        }
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        if (ecdhPeerCertificate != null)
        {
            // For ecdsa_fixed_ecdh and rsa_fixed_ecdh, the key arrived in the client certificate
            return;
        }

        byte[] point = TlsUtils.readOpaque8(input);

        processEphemeral(serverECPointFormats, point);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        if (agreementCredentials != null)
        {
            return agreementCredentials.generateAgreement(ecdhPeerCertificate);
        }

        if (agreement != null)
        {
            return agreement.calculateSecret();
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void generateEphemeral(OutputStream output) throws IOException
    {
        byte[] point = agreement.generateEphemeral();
        TlsUtils.writeOpaque8(point, output);
    }

    protected void processEphemeral(short[] localECPointFormats, byte[] point) throws IOException
    {
        TlsECCUtils.checkPointEncoding(localECPointFormats, ecConfig.getNamedGroup(), point);

        this.agreement.receivePeerValue(point);
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

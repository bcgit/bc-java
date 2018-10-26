package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS ECDH_anon key exchange (see RFC 4492).
 */
public class TlsECDHanonKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.ECDH_anon:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsECConfigVerifier ecConfigVerifier;
    protected TlsECConfig ecConfig;
    protected short[] clientECPointFormats, serverECPointFormats;

    protected TlsAgreement agreement;

    public TlsECDHanonKeyExchange(int keyExchange, TlsECConfigVerifier ecConfigVerifier, short[] clientECPointFormats,
        short[] serverECPointFormats)
    {
        this(keyExchange, ecConfigVerifier, null, clientECPointFormats, serverECPointFormats);
    }

    public TlsECDHanonKeyExchange(int keyExchange, TlsECConfig ecConfig, short[] serverECPointFormats)
    {
        this(keyExchange, null, ecConfig, null, serverECPointFormats);
    }

    private TlsECDHanonKeyExchange(int keyExchange, TlsECConfigVerifier ecConfigVerifier, TlsECConfig ecConfig,
        short[] clientECPointFormats, short[] serverECPointFormats)
    {
        super(checkKeyExchange(keyExchange), null);

        this.ecConfigVerifier = ecConfigVerifier;
        this.ecConfig = ecConfig;
        this.clientECPointFormats = clientECPointFormats;
        this.serverECPointFormats = serverECPointFormats;
    }

    public void skipServerCredentials() throws IOException
    {
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        TlsECCUtils.writeECConfig(ecConfig, buf);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        generateEphemeral(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        this.ecConfig = TlsECCUtils.receiveECConfig(ecConfigVerifier, serverECPointFormats, input);

        byte[] point = TlsUtils.readOpaque8(input);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        processEphemeral(clientECPointFormats, point);
    }

    public short[] getClientCertificateTypes()
    {
        return null;
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        generateEphemeral(output);
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        byte[] point = TlsUtils.readOpaque8(input);

        processEphemeral(serverECPointFormats, point);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        return agreement.calculateSecret();
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
}

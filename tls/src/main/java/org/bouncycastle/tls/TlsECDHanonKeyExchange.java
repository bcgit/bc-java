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

    protected TlsECConfig ecConfig;

    protected TlsAgreement agreement;

    public TlsECDHanonKeyExchange(int keyExchange)
    {
        this(keyExchange, null);
    }

    public TlsECDHanonKeyExchange(int keyExchange, TlsECConfig ecConfig)
    {
        super(checkKeyExchange(keyExchange));

        this.ecConfig = ecConfig;
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
        this.ecConfig = TlsECCUtils.receiveECDHConfig(context, input);

        byte[] point = TlsUtils.readOpaque8(input, 1);

        this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

        processEphemeral(point);
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
        byte[] point = TlsUtils.readOpaque8(input, 1);

        processEphemeral(point);
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

    protected void processEphemeral(byte[] point) throws IOException
    {
        TlsECCUtils.checkPointEncoding(ecConfig.getNamedGroup(), point);

        this.agreement.receivePeerValue(point);
    }
}

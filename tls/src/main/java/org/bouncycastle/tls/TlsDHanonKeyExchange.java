package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * (D)TLS DH_anon key exchange.
 */
public class TlsDHanonKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DH_anon:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsDHGroupVerifier dhGroupVerifier;
    protected TlsDHConfig dhConfig;

    protected TlsAgreement agreement;

    public TlsDHanonKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
    {
        this(keyExchange, dhGroupVerifier, null);
    }

    public TlsDHanonKeyExchange(int keyExchange, TlsDHConfig dhConfig)
    {
        this(keyExchange, null, dhConfig);
    }

    private TlsDHanonKeyExchange(int keyExchange, TlsDHGroupVerifier dhGroupVerifier, TlsDHConfig dhConfig)
    {
        super(checkKeyExchange(keyExchange));

        this.dhGroupVerifier = dhGroupVerifier;
        this.dhConfig = dhConfig;
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

        TlsDHUtils.writeDHConfig(dhConfig, buf);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        byte[] y = agreement.generateEphemeral();

        TlsUtils.writeOpaque16(y, buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        this.dhConfig = TlsDHUtils.receiveDHConfig(context, dhGroupVerifier, input);

        byte[] y = TlsUtils.readOpaque16(input, 1);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        agreement.receivePeerValue(y);
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
        byte[] y = agreement.generateEphemeral();

        TlsUtils.writeOpaque16(y, output);
    }

    public void processClientCertificate(Certificate clientCertificate) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        byte[] y = TlsUtils.readOpaque16(input, 1);

        agreement.receivePeerValue(y);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        return agreement.calculateSecret();
    }
}

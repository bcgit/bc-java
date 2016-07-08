package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.util.io.TeeInputStream;

public class TlsDHEKeyExchange
    extends TlsDHKeyExchange
{
    protected TlsSignerCredentials serverCredentials = null;

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfigVerifier dhConfigVerifier)
    {
        super(keyExchange, supportedSignatureAlgorithms, dhConfigVerifier);
    }

    public TlsDHEKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsDHConfig dhConfig)
    {
        super(keyExchange, supportedSignatureAlgorithms, dhConfig);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        if (!(serverCredentials instanceof TlsSignerCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // TODO[tls-ops] Process the server certificate differently on the server side 
        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials)serverCredentials;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        if (this.dhConfig == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        DigestInputBuffer buf = new DigestInputBuffer();

        TlsDHUtils.writeDHConfig(dhConfig, buf);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        generateEphemeral(buf);

        DigitallySigned signedParams = TlsUtils.generateServerKeyExchangeSignature(context, serverCredentials, buf);

        signedParams.encode(buf);

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        DigestInputBuffer buf = new DigestInputBuffer();
        InputStream teeIn = new TeeInputStream(input, buf);

        this.dhConfig = TlsDHUtils.receiveDHConfig(dhConfigVerifier, teeIn);

        byte[] y = TlsUtils.readOpaque16(teeIn);

        DigitallySigned signedParams = parseSignature(input);

        TlsUtils.verifyServerKeyExchangeSignature(context, tlsSigner, serverPublicKey, buf, signedParams);

        this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

        processEphemeral(y);
    }
}

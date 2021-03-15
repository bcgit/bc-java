package org.bouncycastle.tls.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcGMSSLCredentials;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Vector;

class MockGMSSLServer
    extends DefaultTlsServer
{

    MockGMSSLServer()
    {
        super(new BcTlsCrypto(new SecureRandom()));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("GMSSL server raised alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("GMSSL server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {

    }

    public ProtocolVersion getServerVersion() throws IOException
    {
//        ProtocolVersion serverVersion = super.getServerVersion();
//        System.out.println("GMSSL server negotiated " + serverVersion);
        return ProtocolVersion.GMSSLv11;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        return null;
    }

    public void notifyClientCertificate(org.bouncycastle.tls.Certificate clientCertificate) throws IOException
    {

    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        byte[] tlsServerEndPoint = context.exportChannelBinding(ChannelBinding.tls_server_end_point);
        System.out.println("Server 'tls-server-end-point': " + hex(tlsServerEndPoint));

        byte[] tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);
        System.out.println("Server 'tls-unique': " + hex(tlsUnique));
    }

    @Override
    public TlsCredentials getCredentials() throws IOException
    {
        final Certificate certList = TlsTestUtils.loadCertificateChain(this.context, new String[]{
                "x509-server-sm2-sign.pem", "x509-server-sm2-enc.pem"});
        final AsymmetricKeyParameter signKey = TlsTestUtils.loadBcPrivateKeyResource("x509-server-key-sm2-sign.pem");
        final AsymmetricKeyParameter encKey = TlsTestUtils.loadBcPrivateKeyResource("x509-server-key-sm2-enc.pem");
        return new BcGMSSLCredentials((BcTlsCrypto) getCrypto(), certList, signKey, encKey);
    }

    @Override
    public boolean shouldUseGMTUnixTime()
    {
        return true;
    }

    protected int[] getSupportedCipherSuites()
    {
        return new int[]{CipherSuite.GMSSL_ECC_SM4_SM3};
    }

    protected ProtocolVersion[] getSupportedVersions()
    {
        return ProtocolVersion.GMSSLv11.only();
    }

    protected String hex(byte[] data)
    {
        return data == null ? "(null)" : Hex.toHexString(data);
    }

}

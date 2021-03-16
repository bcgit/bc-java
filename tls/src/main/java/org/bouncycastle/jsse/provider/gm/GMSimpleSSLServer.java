package org.bouncycastle.jsse.provider.gm;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcGMSSLCredentials;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;

/**
 * Simple GMSSL Server
 *
 * @author Cliven
 * @since 2021-03-16 09:31:14
 */
public class GMSimpleSSLServer
    extends DefaultTlsServer
{
    /*
     * contain two cert, first for sign, second for encrypt
     */
    protected Certificate certList;
    protected AsymmetricKeyParameter signKey;
    protected AsymmetricKeyParameter encKey;

    /**
     * Create GMSSL Server Instance
     *
     * @param crypto  crypto
     * @param certList contain two cert, first for sign, second for encrypt
     * @param signKey sign private key
     * @param encKey encrypt private key
     */
    public GMSimpleSSLServer(TlsCrypto crypto, Certificate certList, AsymmetricKeyParameter signKey, AsymmetricKeyParameter encKey)
    {
        super(crypto);
        this.certList = certList;
        this.signKey = signKey;
        this.encKey = encKey;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
//        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
//        out.println("GMSSL server raised alert: " + AlertLevel.getText(alertLevel)
//            + ", " + AlertDescription.getText(alertDescription));
//        if (message != null)
//        {
//            out.println("> " + message);
//        }
//        if (cause != null)
//        {
//            cause.printStackTrace(out);
//        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
//        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
//        out.println("GMSSL server received alert: " + AlertLevel.getText(alertLevel)
//            + ", " + AlertDescription.getText(alertDescription));
    }

    @Override
    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {

    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        return ProtocolVersion.GMSSLv11;
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        return null;
    }

    public void notifyClientCertificate(Certificate clientCertificate) throws IOException
    {

    }

    public void notifyHandshakeComplete() throws IOException
    {

    }

    @Override
    public TlsCredentials getCredentials() throws IOException
    {
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

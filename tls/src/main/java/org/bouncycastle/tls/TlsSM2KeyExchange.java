package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsVerifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * GMSSL SM2 exchange.
 *
 * @author Cliven
 */
public class TlsSM2KeyExchange extends AbstractTlsKeyExchange
{


    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.SM2:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsCredentialedDecryptor serverCredentials = null;
    /**
     * first cert of certificate list
     * use to sign server side key exchange message
     * <p>
     * digitally-signed struct
     * {
     * opaque client_random[32];
     * opaque server_random[32];
     * opaque ASN.1Cert<1..2^24-1>
     * } signed params
     */
    protected TlsCertificate serverSigCertificate;

    /**
     * second cert of certificate list
     * use to encrypt client generate preMasterSecret.
     */
    protected TlsCertificate serverEncCertificate;
    protected TlsSecret preMasterSecret;

    public TlsSM2KeyExchange(int keyExchange)
    {
        super(checkKeyExchange(keyExchange));
    }

    public void skipServerCredentials() throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        this.serverCredentials = TlsUtils.requireDecryptorCredentials(serverCredentials);
    }

    @Override
    public void processServerKeyExchange(InputStream input) throws IOException
    {

        final int n = TlsUtils.readUint16(input);
        final byte[] signature = TlsUtils.readFully(n, input);
        /*
         * digitally-signed struct
         * {
         *     opaque client_random[32];
         *     opaque server_random[32];
         *     opaque ASN.1Cert<1..2^24-1>
         * } signed params
         *
         * the ASN.1Cert field is encrypt certificate
         */
        final SecurityParameters securityParameters = context.getSecurityParametersHandshake();
        final byte[] clientRandom = securityParameters.getClientRandom();
        final byte[] serverRandom = securityParameters.getServerRandom();
        final byte[] encCert = serverEncCertificate.getEncoded();
        int totalSize = clientRandom.length + serverRandom.length + 3 + encCert.length;
        byte[] plaintext = new byte[totalSize];
        System.arraycopy(clientRandom, 0, plaintext, 0, 32);
        System.arraycopy(serverRandom, 0, plaintext, 32, 32);
        plaintext[64] = (byte) (0xff & (encCert.length >> 16));
        plaintext[65] = (byte) (0xff & (encCert.length >> 8));
        plaintext[66] = (byte) (0xff & (encCert.length));
        System.arraycopy(encCert, 0, plaintext, 67, encCert.length);
        final TlsVerifier verifier = serverSigCertificate.createVerifier(SignatureAlgorithm.sm2);

        DigitallySigned digitallySigned = new DigitallySigned(SignatureAndHashAlgorithm.sm2, signature);
        final boolean pass = verifier.verifyRawSignature(digitallySigned, plaintext);
        if(!pass)
        {
            throw new TlsFatalAlertReceived(AlertDescription.illegal_parameter);
        }
//        this.serverSigCertificate.createVerifier()
        return;
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        // GMSSL has two certificates, first is for signing the second is for encryption
        if(serverCertificate.getLength() < 2)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        // sign cert
        this.serverSigCertificate = serverCertificate.getCertificateAt(0).useInRole(ConnectionEnd.server, KeyExchangeAlgorithm.SM2);
        // encrypt cert
        this.serverEncCertificate = serverCertificate.getCertificateAt(1).useInRole(ConnectionEnd.server, KeyExchangeAlgorithm.SM2);
    }

    public short[] getClientCertificateTypes()
    {
        return new short[]{ClientCertificateType.sm2_encrypt};
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        TlsUtils.requireSignerCredentials(clientCredentials);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
//        // TODO: SM2加密工具
//        this.preMasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, serverCertificate, output);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
//        byte[] encryptedPreMasterSecret = TlsUtils.readEncryptedPMS(context, input);
//        // TODO: 解密工具
//        this.preMasterSecret = serverCredentials.decrypt(new TlsCryptoParameters(context), encryptedPreMasterSecret);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        TlsSecret tmp = this.preMasterSecret;
        this.preMasterSecret = null;
        return tmp;
    }
}

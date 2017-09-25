package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * (D)TLS SRP key exchange (RFC 5054).
 */
public class TlsSRPKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.SRP:
        case KeyExchangeAlgorithm.SRP_DSS:
        case KeyExchangeAlgorithm.SRP_RSA:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsSRPConfigVerifier srpConfigVerifier;
    protected byte[] identity;
    protected byte[] password;

    protected TlsSRPConfig srpConfig = null;
    protected TlsSRP6Client srpClient = null;
    protected TlsSRP6Server srpServer = null;
    protected BigInteger srpPeerCredentials = null;
    protected BigInteger srpVerifier = null;
    protected byte[] srpSalt = null;

    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsVerifier verifier = null;

    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsSRPConfigVerifier srpConfigVerifier,
        byte[] identity, byte[] password)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.srpConfigVerifier = srpConfigVerifier;
        this.identity = identity;
        this.password = password;
    }

    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity,
        TlsSRPLoginParameters loginParameters)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.identity = identity;
        this.srpConfig = loginParameters.getConfig();
        this.srpVerifier = loginParameters.getVerifier();
        this.srpSalt = loginParameters.getSalt();
    }

    public void skipServerCredentials() throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.SRP)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.SRP)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (!(serverCredentials instanceof TlsCredentialedSigner))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.serverCredentials = (TlsCredentialedSigner)serverCredentials;
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.SRP)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        checkServerCertSigAlg(serverCertificate);

        this.verifier = serverCertificate.getCertificateAt(0)
            .createVerifier(TlsUtils.getSignatureAlgorithm(keyExchange));
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        srpServer = context.getCrypto().createSRP6Server(srpConfig, srpVerifier);

        BigInteger B = srpServer.generateServerCredentials();

        BigInteger[] ng = srpConfig.getExplicitNG();
        ServerSRPParams srpParams = new ServerSRPParams(ng[0], ng[1], srpSalt, B);

        DigestInputBuffer buf = new DigestInputBuffer();

        srpParams.encode(buf);

        if (serverCredentials != null)
        {
            DigitallySigned signedParams = TlsUtils.generateServerKeyExchangeSignature(context, serverCredentials, buf);

            signedParams.encode(buf);
        }

        return buf.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        DigestInputBuffer buf = null;
        InputStream teeIn = input;

        if (keyExchange != KeyExchangeAlgorithm.SRP)
        {
            buf = new DigestInputBuffer();
            teeIn = new TeeInputStream(input, buf);
        }

        ServerSRPParams srpParams = ServerSRPParams.parse(teeIn);

        if (buf != null)
        {
            DigitallySigned signedParams = parseSignature(input);

            TlsUtils.verifyServerKeyExchangeSignature(context, verifier, buf, signedParams);
        }

        this.srpConfig = new TlsSRPConfig();
        srpConfig.setExplicitNG(new BigInteger[]{ srpParams.getN(), srpParams.getG() });

        if (!srpConfigVerifier.accept(srpConfig))
        {
            throw new TlsFatalAlert(AlertDescription.insufficient_security);
        }

        this.srpSalt = srpParams.getS();

        /*
         * RFC 5054 2.5.3: The client MUST abort the handshake with an "illegal_parameter" alert if
         * B % N = 0.
         */
        this.srpPeerCredentials = validatePublicValue(srpParams.getN(), srpParams.getB());
        this.srpClient = context.getCrypto().createSRP6Client(srpConfig);
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        BigInteger A = srpClient.generateClientCredentials(srpSalt, identity, password);
        TlsSRPUtils.writeSRPParameter(A, output);

        context.getSecurityParameters().srpIdentity = Arrays.clone(identity);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        /*
         * RFC 5054 2.5.4: The server MUST abort the handshake with an "illegal_parameter" alert if
         * A % N = 0.
         */
        this.srpPeerCredentials = validatePublicValue(srpConfig.getExplicitNG()[0], TlsSRPUtils.readSRPParameter(input));
        context.getSecurityParameters().srpIdentity = Arrays.clone(identity);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        BigInteger S = srpServer != null
            ?   srpServer.calculateSecret(srpPeerCredentials)
            :   srpClient.calculateSecret(srpPeerCredentials);

        // TODO Check if this needs to be a fixed size
        return context.getCrypto().createSecret(BigIntegers.asUnsignedByteArray(S));
    }

    public static BigInteger validatePublicValue(BigInteger N, BigInteger val)
        throws IOException
    {
        val = val.mod(N);

        // Check that val % N != 0
        if (val.equals(BigInteger.ZERO))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return val;
    }
}

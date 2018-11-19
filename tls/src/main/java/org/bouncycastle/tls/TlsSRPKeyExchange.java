package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSRP6Client;
import org.bouncycastle.tls.crypto.TlsSRP6Server;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
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

    protected TlsSRPIdentity srpIdentity;
    protected TlsSRPConfigVerifier srpConfigVerifier;
    protected TlsCertificate serverCertificate = null;
    protected byte[] srpSalt = null;
    protected TlsSRP6Client srpClient = null;

    protected TlsSRPLoginParameters srpLoginParameters;
    protected TlsCredentialedSigner serverCredentials = null;
    protected TlsSRP6Server srpServer = null;

    protected BigInteger srpPeerCredentials = null;

    public TlsSRPKeyExchange(int keyExchange, TlsSRPIdentity srpIdentity, TlsSRPConfigVerifier srpConfigVerifier)
    {
        super(checkKeyExchange(keyExchange));

        this.srpIdentity = srpIdentity;
        this.srpConfigVerifier = srpConfigVerifier;
    }

    public TlsSRPKeyExchange(int keyExchange, TlsSRPLoginParameters srpLoginParameters)
    {
        super(checkKeyExchange(keyExchange));

        this.srpLoginParameters = srpLoginParameters;
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

        this.serverCredentials = TlsUtils.requireSignerCredentials(serverCredentials);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.SRP)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.serverCertificate = serverCertificate.getCertificateAt(0);
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        TlsSRPConfig config = srpLoginParameters.getConfig();

        srpServer = context.getCrypto().createSRP6Server(config, srpLoginParameters.getVerifier());

        BigInteger B = srpServer.generateServerCredentials();

        BigInteger[] ng = config.getExplicitNG();
        ServerSRPParams srpParams = new ServerSRPParams(ng[0], ng[1], srpLoginParameters.getSalt(), B);

        DigestInputBuffer digestBuffer = new DigestInputBuffer();

        srpParams.encode(digestBuffer);

        if (serverCredentials != null)
        {
            TlsUtils.generateServerKeyExchangeSignature(context, serverCredentials, digestBuffer);
        }

        return digestBuffer.toByteArray();
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        DigestInputBuffer digestBuffer = null;
        InputStream teeIn = input;

        if (keyExchange != KeyExchangeAlgorithm.SRP)
        {
            digestBuffer = new DigestInputBuffer();
            teeIn = new TeeInputStream(input, digestBuffer);
        }

        ServerSRPParams srpParams = ServerSRPParams.parse(teeIn);

        if (digestBuffer != null)
        {
            TlsUtils.verifyServerKeyExchangeSignature(context, input, serverCertificate, digestBuffer);
        }

        TlsSRPConfig config = new TlsSRPConfig();
        config.setExplicitNG(new BigInteger[]{ srpParams.getN(), srpParams.getG() });

        if (!srpConfigVerifier.accept(config))
        {
            throw new TlsFatalAlert(AlertDescription.insufficient_security);
        }

        this.srpSalt = srpParams.getS();

        /*
         * RFC 5054 2.5.3: The client MUST abort the handshake with an "illegal_parameter" alert if
         * B % N = 0.
         */
        this.srpPeerCredentials = validatePublicValue(srpParams.getN(), srpParams.getB());
        this.srpClient = context.getCrypto().createSRP6Client(config);
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void generateClientKeyExchange(OutputStream output) throws IOException
    {
        byte[] identity = srpIdentity.getSRPIdentity();
        byte[] password = srpIdentity.getSRPPassword();

        BigInteger A = srpClient.generateClientCredentials(srpSalt, identity, password);
        TlsSRPUtils.writeSRPParameter(A, output);

        context.getSecurityParametersHandshake().srpIdentity = Arrays.clone(identity);
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        /*
         * RFC 5054 2.5.4: The server MUST abort the handshake with an "illegal_parameter" alert if
         * A % N = 0.
         */
        this.srpPeerCredentials = validatePublicValue(srpLoginParameters.getConfig().getExplicitNG()[0],
            TlsSRPUtils.readSRPParameter(input));
        context.getSecurityParametersHandshake().srpIdentity = Arrays.clone(srpLoginParameters.getIdentity());
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

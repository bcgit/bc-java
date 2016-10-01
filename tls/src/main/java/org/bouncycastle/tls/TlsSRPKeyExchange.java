package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
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
    protected SRP6Client srpClient = null;
    protected SRP6Server srpServer = null;
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
        this.srpClient = new SRP6Client();
    }

    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity,
        TlsSRPLoginParameters loginParameters)
    {
        super(checkKeyExchange(keyExchange), supportedSignatureAlgorithms);

        this.identity = identity;
        this.srpServer = new SRP6Server();
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

        this.verifier = serverCertificate.getCertificateAt(context, 0)
            .createVerifier(TlsUtils.getSignatureAlgorithm(keyExchange));
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        // TODO[tls-ops] Need SRP support in TlsCrypto
        SRP6GroupParameters srpGroup = getGroupParameters();
        
        // TODO[tls-ops] Construct digest via TlsCrypto
        srpServer.init(srpGroup, srpVerifier, new SHA1Digest(), context.getCrypto().getSecureRandom());
        BigInteger B = srpServer.generateServerCredentials();

        ServerSRPParams srpParams = new ServerSRPParams(srpGroup.getN(), srpGroup.getG(), srpSalt, B);

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
        try
        {
            this.srpPeerCredentials = SRP6Util.validatePublicValue(srpParams.getN(), srpParams.getB());
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }

        // TODO[tls-ops] Need SRP support in TlsCrypto
        SRP6GroupParameters srpGroup = getGroupParameters();
        this.srpClient.init(srpGroup, new SHA1Digest(), context.getCrypto().getSecureRandom());
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
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
        try
        {
            this.srpPeerCredentials = SRP6Util.validatePublicValue(srpConfig.getExplicitNG()[0], TlsSRPUtils.readSRPParameter(input));
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }

        context.getSecurityParameters().srpIdentity = Arrays.clone(identity);
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        try
        {
            BigInteger S = srpServer != null
                ?   srpServer.calculateSecret(srpPeerCredentials)
                :   srpClient.calculateSecret(srpPeerCredentials);

            // TODO Check if this needs to be a fixed size
            return context.getCrypto().createSecret(BigIntegers.asUnsignedByteArray(S));
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }
    }

    // TODO[tls-ops] Need SRP support in TlsCrypto
    protected SRP6GroupParameters getGroupParameters()
    {
        BigInteger[] ng = srpConfig.getExplicitNG();
        return new SRP6GroupParameters(ng[0], ng[1]);
    }
}

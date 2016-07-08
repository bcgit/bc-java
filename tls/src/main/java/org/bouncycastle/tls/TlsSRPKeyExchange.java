package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * (D)TLS SRP key exchange (RFC 5054).
 */
public class TlsSRPKeyExchange extends AbstractTlsKeyExchange
{
    protected static TlsSigner createSigner(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.SRP:
            return null;
        case KeyExchangeAlgorithm.SRP_RSA:
            return new TlsRSASigner();
        case KeyExchangeAlgorithm.SRP_DSS:
            return new TlsDSSSigner();
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }
    
    protected TlsSigner tlsSigner;
    protected TlsSRPGroupVerifier groupVerifier;
    protected byte[] identity;
    protected byte[] password;

    protected AsymmetricKeyParameter serverPublicKey = null;

    protected SRP6GroupParameters srpGroup = null;
    protected SRP6Client srpClient = null;
    protected SRP6Server srpServer = null;
    protected BigInteger srpPeerCredentials = null;
    protected BigInteger srpVerifier = null;
    protected byte[] srpSalt = null;

    protected TlsSignerCredentials serverCredentials = null;

    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsSRPGroupVerifier groupVerifier,
        byte[] identity, byte[] password)
    {
        super(keyExchange, supportedSignatureAlgorithms);

        this.tlsSigner = createSigner(keyExchange);
        this.groupVerifier = groupVerifier;
        this.identity = identity;
        this.password = password;
        this.srpClient = new SRP6Client();
    }

    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, byte[] identity,
        TlsSRPLoginParameters loginParameters)
    {
        super(keyExchange, supportedSignatureAlgorithms);

        this.tlsSigner = createSigner(keyExchange);
        this.identity = identity;
        this.srpServer = new SRP6Server();
        this.srpGroup = loginParameters.getGroup();
        this.srpVerifier = loginParameters.getVerifier();
        this.srpSalt = loginParameters.getSalt();
    }

    public void init(TlsContext context)
    {
        super.init(context);

        if (this.tlsSigner != null)
        {
            this.tlsSigner.init(context);
        }
    }

    public void skipServerCredentials() throws IOException
    {
        if (tlsSigner != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (tlsSigner == null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        org.bouncycastle.asn1.x509.Certificate x509Cert = serverCertificate.getCertificateAt(0);

        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
        try
        {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }

        if (!tlsSigner.isValidPublicKey(this.serverPublicKey))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        TlsUtils.validateKeyUsage(x509Cert, KeyUsage.digitalSignature);

        super.processServerCertificate(serverCertificate);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        if ((keyExchange == KeyExchangeAlgorithm.SRP) || !(serverCredentials instanceof TlsSignerCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // TODO[tls-ops] Process the server certificate differently on the server side 
        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsSignerCredentials)serverCredentials;
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        srpServer.init(srpGroup, srpVerifier, TlsUtils.createHash(HashAlgorithm.sha1), context.getSecureRandom());
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

        if (tlsSigner != null)
        {
            buf = new DigestInputBuffer();
            teeIn = new TeeInputStream(input, buf);
        }

        ServerSRPParams srpParams = ServerSRPParams.parse(teeIn);

        if (buf != null)
        {
            DigitallySigned signedParams = parseSignature(input);

            TlsUtils.verifyServerKeyExchangeSignature(context, tlsSigner, serverPublicKey, buf, signedParams);
        }

        this.srpGroup = new SRP6GroupParameters(srpParams.getN(), srpParams.getG());

        if (!groupVerifier.accept(srpGroup))
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
            this.srpPeerCredentials = SRP6Util.validatePublicValue(srpGroup.getN(), srpParams.getB());
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
        }

        this.srpClient.init(srpGroup, TlsUtils.createHash(HashAlgorithm.sha1), context.getSecureRandom());
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
            this.srpPeerCredentials = SRP6Util.validatePublicValue(srpGroup.getN(), TlsSRPUtils.readSRPParameter(input));
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
}

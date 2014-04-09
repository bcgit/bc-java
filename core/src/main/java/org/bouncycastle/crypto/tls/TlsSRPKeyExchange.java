package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * TLS 1.1 SRP key exchange (RFC 5054).
 */
public class TlsSRPKeyExchange extends AbstractTlsKeyExchange
{
    protected TlsSigner tlsSigner;
    protected byte[] identity;
    protected byte[] password;

    protected AsymmetricKeyParameter serverPublicKey = null;

    protected SRPPrimeVerifier Nverifier;
    protected byte[] s = null;
    protected BigInteger B = null;
    protected BigInteger N = null;
    protected BigInteger g = null;
    protected BigInteger A = null;
    protected BigInteger v = null;
    protected SRP6Client srpClient = null;
    protected SRP6Server srpServer = null;

    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, SRPPrimeVerifier Nverifier,
            byte[] identity, byte[] password)
    {
        this(keyExchange, supportedSignatureAlgorithms);
        this.Nverifier = Nverifier;
        this.identity = identity;
        this.password = password;
        this.srpClient = new SRP6Client();
    }
    
    public TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms,
            BigInteger v, byte[] s, BigInteger N, BigInteger g)
    {
        this(keyExchange, supportedSignatureAlgorithms);
        this.v = v;
        this.s = s;
        this.N = N;
        this.g = g;
        this.srpServer = new SRP6Server();
    }
    
    private TlsSRPKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms) {
        super(keyExchange, supportedSignatureAlgorithms);
        
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.SRP:
            this.tlsSigner = null;
            break;
        case KeyExchangeAlgorithm.SRP_RSA:
            this.tlsSigner = new TlsRSASigner();
            break;
        case KeyExchangeAlgorithm.SRP_DSS:
            this.tlsSigner = new TlsDSSSigner();
            break;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    public void init(TlsContext context)
    {
        super.init(context);

        if (this.tlsSigner != null) {
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
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        if (!tlsSigner.isValidPublicKey(this.serverPublicKey))
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown);
        }

        TlsUtils.validateKeyUsage(x509Cert, KeyUsage.digitalSignature);

        super.processServerCertificate(serverCertificate);
    }

    public boolean requiresServerKeyExchange()
    {
        return true;
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        SecurityParameters securityParameters = context.getSecurityParameters();

        SignerInputBuffer buf = null;
        InputStream teeIn = input;

        if (tlsSigner != null)
        {
            buf = new SignerInputBuffer();
            teeIn = new TeeInputStream(input, buf);
        }

        byte[] NBytes = TlsUtils.readOpaque16(teeIn);
        byte[] gBytes = TlsUtils.readOpaque16(teeIn);
        byte[] sBytes = TlsUtils.readOpaque8(teeIn);
        byte[] BBytes = TlsUtils.readOpaque16(teeIn);

        if (buf != null)
        {
            DigitallySigned signed_params = DigitallySigned.parse(context, input);

            Signer signer = initVerifyer(tlsSigner, signed_params.getAlgorithm(), securityParameters);
            buf.updateSigner(signer);
            if (!signer.verifySignature(signed_params.getSignature()))
            {
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }
        }

        BigInteger N = new BigInteger(1, NBytes);
        BigInteger g = new BigInteger(1, gBytes);

        /*
         * RFC 5054 3.2: clients SHOULD only accept group parameters that
         * come from a trusted source, such as those listed in Appendix A,
         * or parameters configured locally by a trusted administrator.
         */
        if (!Nverifier.accept(N))
        {
            throw new TlsFatalAlert(AlertDescription.insufficient_security);
        }

        this.s = sBytes;

        /*
         * RFC 5054 2.5.3: The client MUST abort the handshake with an "illegal_parameter" alert if
         * B % N = 0.
         */
        try
        {
            this.B = SRP6Util.validatePublicValue(N, new BigInteger(1, BBytes));
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        this.srpClient.init(N, g, new SHA1Digest(), context.getSecureRandom());
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
        A = srpClient.generateClientCredentials(s, this.identity, this.password);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(A), output);
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        try
        {
            // TODO Check if this needs to be a fixed size
            if (srpServer == null)
            {
                return BigIntegers.asUnsignedByteArray(srpClient.calculateSecret(B));
            }
            else
            {
                return BigIntegers.asUnsignedByteArray(srpServer.calculateSecret(A));
            }
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    protected Signer initVerifyer(TlsSigner tlsSigner, SignatureAndHashAlgorithm algorithm, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(algorithm, this.serverPublicKey);
        signer.update(securityParameters.clientRandom, 0, securityParameters.clientRandom.length);
        signer.update(securityParameters.serverRandom, 0, securityParameters.serverRandom.length);
        return signer;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        srpServer.init(N, g, v, new SHA1Digest(), context.getSecureRandom());
        B = srpServer.generateServerCredentials();
        
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(56);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(N), buffer);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(g), buffer);
        TlsUtils.writeOpaque8(s, buffer);
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(B), buffer);
        return buffer.toByteArray();
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        /*
         * RFC 5054 2.5.4: The client MUST abort the handshake with an "illegal_parameter" alert if
         * A % N = 0.
         */
        try
        {
            A = SRP6Util.validatePublicValue(N, new BigInteger(1, TlsUtils.readOpaque16(input)));
        }
        catch (CryptoException e)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }
}

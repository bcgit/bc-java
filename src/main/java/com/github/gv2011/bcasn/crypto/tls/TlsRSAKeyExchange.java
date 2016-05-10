package com.github.gv2011.bcasn.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import com.github.gv2011.bcasn.asn1.x509.KeyUsage;
import com.github.gv2011.bcasn.asn1.x509.SubjectPublicKeyInfo;
import com.github.gv2011.bcasn.crypto.params.AsymmetricKeyParameter;
import com.github.gv2011.bcasn.crypto.params.RSAKeyParameters;
import com.github.gv2011.bcasn.crypto.util.PublicKeyFactory;
import com.github.gv2011.bcasn.util.io.Streams;

/**
 * (D)TLS and SSLv3 RSA key exchange.
 */
public class TlsRSAKeyExchange
    extends AbstractTlsKeyExchange
{
    protected AsymmetricKeyParameter serverPublicKey = null;

    protected RSAKeyParameters rsaServerPublicKey = null;

    protected TlsEncryptionCredentials serverCredentials = null;

    protected byte[] premasterSecret;

    public TlsRSAKeyExchange(Vector supportedSignatureAlgorithms)
    {
        super(KeyExchangeAlgorithm.RSA, supportedSignatureAlgorithms);
    }

    public void skipServerCredentials()
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void processServerCredentials(TlsCredentials serverCredentials)
        throws IOException
    {
        if (!(serverCredentials instanceof TlsEncryptionCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsEncryptionCredentials)serverCredentials;
    }

    public void processServerCertificate(Certificate serverCertificate)
        throws IOException
    {
        if (serverCertificate.isEmpty())
        {
            throw new TlsFatalAlert(AlertDescription.bad_certificate);
        }

        com.github.gv2011.bcasn.asn1.x509.Certificate x509Cert = serverCertificate.getCertificateAt(0);

        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
        try
        {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
        }

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);

        TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);

        super.processServerCertificate(serverCertificate);
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException
    {
        short[] types = certificateRequest.getCertificateTypes();
        for (int i = 0; i < types.length; ++i)
        {
            switch (types[i])
            {
            case ClientCertificateType.rsa_sign:
            case ClientCertificateType.dss_sign:
            case ClientCertificateType.ecdsa_sign:
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
    }

    public void processClientCredentials(TlsCredentials clientCredentials)
        throws IOException
    {
        if (!(clientCredentials instanceof TlsSignerCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void generateClientKeyExchange(OutputStream output)
        throws IOException
    {
        this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, rsaServerPublicKey, output);
    }

    public void processClientKeyExchange(InputStream input)
        throws IOException
    {
        byte[] encryptedPreMasterSecret;
        if (TlsUtils.isSSL(context))
        {
            // TODO Do any SSLv3 clients actually include the length?
            encryptedPreMasterSecret = Streams.readAll(input);
        }
        else
        {
            encryptedPreMasterSecret = TlsUtils.readOpaque16(input);
        }

        this.premasterSecret = serverCredentials.decryptPreMasterSecret(encryptedPreMasterSecret);
    }

    public byte[] generatePremasterSecret()
        throws IOException
    {
        if (this.premasterSecret == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        byte[] tmp = this.premasterSecret;
        this.premasterSecret = null;
        return tmp;
    }

    // Would be needed to process RSA_EXPORT server key exchange
    // protected void processRSAServerKeyExchange(InputStream is, Signer signer) throws IOException
    // {
    // InputStream sigIn = is;
    // if (signer != null)
    // {
    // sigIn = new SignerInputStream(is, signer);
    // }
    //
    // byte[] modulusBytes = TlsUtils.readOpaque16(sigIn);
    // byte[] exponentBytes = TlsUtils.readOpaque16(sigIn);
    //
    // if (signer != null)
    // {
    // byte[] sigByte = TlsUtils.readOpaque16(is);
    //
    // if (!signer.verifySignature(sigByte))
    // {
    // handler.failWithError(AlertLevel.fatal, AlertDescription.bad_certificate);
    // }
    // }
    //
    // BigInteger modulus = new BigInteger(1, modulusBytes);
    // BigInteger exponent = new BigInteger(1, exponentBytes);
    //
    // this.rsaServerPublicKey = validateRSAPublicKey(new RSAKeyParameters(false, modulus,
    // exponent));
    // }

    protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters key)
        throws IOException
    {
        // TODO What is the minimum bit length required?
        // key.getModulus().bitLength();

        if (!key.getExponent().isProbablePrime(2))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        return key;
    }
}

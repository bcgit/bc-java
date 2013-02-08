package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;

class TlsPSKKeyExchange implements TlsKeyExchange
{
    protected TlsClientContext context;
    protected int keyExchange;
    protected TlsPSKIdentity pskIdentity;

    protected byte[] psk_identity_hint = null;

    protected DHPublicKeyParameters dhAgreeServerPublicKey = null;
    protected DHPrivateKeyParameters dhAgreeClientPrivateKey = null;

    protected AsymmetricKeyParameter serverPublicKey = null;
    protected RSAKeyParameters rsaServerPublicKey = null;
    protected byte[] premasterSecret;

    TlsPSKKeyExchange(TlsClientContext context, int keyExchange, TlsPSKIdentity pskIdentity)
    {
        switch (keyExchange)
        {
            case KeyExchangeAlgorithm.PSK:
            case KeyExchangeAlgorithm.RSA_PSK:
            case KeyExchangeAlgorithm.DHE_PSK:
                break;
            default:
                throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.context = context;
        this.keyExchange = keyExchange;
        this.pskIdentity = pskIdentity;
    }

    public void skipServerCertificate() throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.RSA_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        org.bouncycastle.asn1.x509.Certificate x509Cert = serverCertificate.certs[0];
        SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();

        try
        {
            this.serverPublicKey = PublicKeyFactory.createKey(keyInfo);
        }
        catch (RuntimeException e)
        {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
        }

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters) this.serverPublicKey);

        TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);

        // TODO
        /*
         * Perform various checks per RFC2246 7.4.2: "Unless otherwise
         * specified, the signing algorithm for the certificate must be the same
         * as the algorithm for the certificate key."
         */
    }

    public void skipServerKeyExchange() throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        this.psk_identity_hint = new byte[0];
    }

    public void processServerKeyExchange(InputStream is) throws IOException
    {
        this.psk_identity_hint = TlsUtils.readOpaque16(is);

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            byte[] pBytes = TlsUtils.readOpaque16(is);
            byte[] gBytes = TlsUtils.readOpaque16(is);
            byte[] YsBytes = TlsUtils.readOpaque16(is);

            BigInteger p = new BigInteger(1, pBytes);
            BigInteger g = new BigInteger(1, gBytes);
            BigInteger Ys = new BigInteger(1, YsBytes);

            this.dhAgreeServerPublicKey = TlsDHUtils.validateDHPublicKey(new DHPublicKeyParameters(Ys,
                new DHParameters(p, g)));
        }
        else if (this.psk_identity_hint.length == 0)
        {
            // TODO Should we enforce that this message should have been skipped if hint is empty?
//            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void validateCertificateRequest(CertificateRequest certificateRequest)
        throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.unexpected_message);
    }

    public void skipClientCredentials() throws IOException
    {
    	// OK
    }

    public void processClientCredentials(TlsCredentials clientCredentials) throws IOException
    {
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    public void generateClientKeyExchange(OutputStream os) throws IOException
    {
    	if (psk_identity_hint == null || psk_identity_hint.length == 0)
    	{
    	    pskIdentity.skipIdentityHint();
    	}
    	else
    	{
            pskIdentity.notifyIdentityHint(psk_identity_hint);
    	}

    	byte[] psk_identity = pskIdentity.getPSKIdentity();

        TlsUtils.writeOpaque16(psk_identity, os);

        if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context,
                this.rsaServerPublicKey, os);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            this.dhAgreeClientPrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(
                context.getSecureRandom(), dhAgreeServerPublicKey.getParameters(), os);
        }
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        byte[] psk = pskIdentity.getPSK();
        byte[] other_secret = generateOtherSecret(psk.length);

        ByteArrayOutputStream buf = new ByteArrayOutputStream(4 + other_secret.length + psk.length);
        TlsUtils.writeOpaque16(other_secret, buf);
        TlsUtils.writeOpaque16(psk, buf);
        return buf.toByteArray();
    }

    protected byte[] generateOtherSecret(int pskLength)
    {
        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            return TlsDHUtils.calculateDHBasicAgreement(dhAgreeServerPublicKey, dhAgreeClientPrivateKey);
        }

        if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            return this.premasterSecret;
        }

        return new byte[pskLength];
    }

    protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters key) throws IOException
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

package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * (D)TLS PSK key exchange (RFC 4279).
 */
public class TlsPSKKeyExchange
    extends AbstractTlsKeyExchange
{
    protected TlsPSKIdentity pskIdentity;
    protected TlsPSKIdentityManager pskIdentityManager;

    protected DHParameters dhParameters;
    protected int[] namedCurves;
    protected short[] clientECPointFormats, serverECPointFormats;

    protected byte[] psk_identity_hint = null;
    protected byte[] psk = null;

    protected DHPrivateKeyParameters dhAgreePrivateKey = null;
    protected DHPublicKeyParameters dhAgreePublicKey = null;

    protected ECPrivateKeyParameters ecAgreePrivateKey = null;
    protected ECPublicKeyParameters ecAgreePublicKey = null;

    protected AsymmetricKeyParameter serverPublicKey = null;
    protected RSAKeyParameters rsaServerPublicKey = null;
    protected TlsEncryptionCredentials serverCredentials = null;
    protected byte[] premasterSecret;

    public TlsPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsPSKIdentity pskIdentity,
        TlsPSKIdentityManager pskIdentityManager, DHParameters dhParameters, int[] namedCurves,
        short[] clientECPointFormats, short[] serverECPointFormats)
    {
        super(keyExchange, supportedSignatureAlgorithms);

        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
        case KeyExchangeAlgorithm.ECDHE_PSK:
        case KeyExchangeAlgorithm.PSK:
        case KeyExchangeAlgorithm.RSA_PSK:
            break;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }

        this.pskIdentity = pskIdentity;
        this.pskIdentityManager = pskIdentityManager;
        this.dhParameters = dhParameters;
        this.namedCurves = namedCurves;
        this.clientECPointFormats = clientECPointFormats;
        this.serverECPointFormats = serverECPointFormats;
    }

    public void skipServerCredentials() throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        if (!(serverCredentials instanceof TlsEncryptionCredentials))
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        processServerCertificate(serverCredentials.getCertificate());

        this.serverCredentials = (TlsEncryptionCredentials)serverCredentials;
    }

    public byte[] generateServerKeyExchange() throws IOException
    {
        this.psk_identity_hint = pskIdentityManager.getHint();

        if (this.psk_identity_hint == null && !requiresServerKeyExchange())
        {
            return null;
        }

        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        if (this.psk_identity_hint == null)
        {
            TlsUtils.writeOpaque16(TlsUtils.EMPTY_BYTES, buf);
        }
        else
        {
            TlsUtils.writeOpaque16(this.psk_identity_hint, buf);
        }

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            if (this.dhParameters == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(),
                this.dhParameters, buf);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            this.ecAgreePrivateKey = TlsECCUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(),
                namedCurves, clientECPointFormats, buf);
        }

        return buf.toByteArray();
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.RSA_PSK)
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

        // Sanity check the PublicKeyFactory
        if (this.serverPublicKey.isPrivate())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.rsaServerPublicKey = validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);

        TlsUtils.validateKeyUsage(x509Cert, KeyUsage.keyEncipherment);

        super.processServerCertificate(serverCertificate);
    }

    public boolean requiresServerKeyExchange()
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
        case KeyExchangeAlgorithm.ECDHE_PSK:
            return true;
        default:
            return false;
        }
    }

    public void processServerKeyExchange(InputStream input) throws IOException
    {
        this.psk_identity_hint = TlsUtils.readOpaque16(input);

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            ServerDHParams serverDHParams = ServerDHParams.parse(input);

            this.dhAgreePublicKey = TlsDHUtils.validateDHPublicKey(serverDHParams.getPublicKey());
            this.dhParameters = dhAgreePublicKey.getParameters();
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            ECDomainParameters ecParams = TlsECCUtils.readECParameters(namedCurves, clientECPointFormats, input);

            byte[] point = TlsUtils.readOpaque8(input);

            this.ecAgreePublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(
                clientECPointFormats, ecParams, point));
        }
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
        if (psk_identity_hint == null)
        {
            pskIdentity.skipIdentityHint();
        }
        else
        {
            pskIdentity.notifyIdentityHint(psk_identity_hint);
        }

        byte[] psk_identity = pskIdentity.getPSKIdentity();
        if (psk_identity == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.psk = pskIdentity.getPSK();
        if (psk == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.writeOpaque16(psk_identity, output);

        context.getSecurityParameters().pskIdentity = Arrays.clone(psk_identity);

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(context.getSecureRandom(),
                dhParameters, output);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            this.ecAgreePrivateKey = TlsECCUtils.generateEphemeralClientKeyExchange(context.getSecureRandom(),
                serverECPointFormats, ecAgreePublicKey.getParameters(), output);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, this.rsaServerPublicKey,
                output);
        }
    }

    public void processClientKeyExchange(InputStream input) throws IOException
    {
        byte[] psk_identity = TlsUtils.readOpaque16(input);

        this.psk = pskIdentityManager.getPSK(psk_identity);
        if (psk == null)
        {
            throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
        }

        context.getSecurityParameters().pskIdentity = psk_identity;

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            BigInteger Yc = TlsDHUtils.readDHParameter(input);

            this.dhAgreePublicKey = TlsDHUtils.validateDHPublicKey(new DHPublicKeyParameters(Yc, dhParameters));
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            byte[] point = TlsUtils.readOpaque8(input);

            ECDomainParameters curve_params = this.ecAgreePrivateKey.getParameters();

            this.ecAgreePublicKey = TlsECCUtils.validateECPublicKey(TlsECCUtils.deserializeECPublicKey(
                serverECPointFormats, curve_params, point));
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
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
    }

    public byte[] generatePremasterSecret() throws IOException
    {
        byte[] other_secret = generateOtherSecret(psk.length);

        ByteArrayOutputStream buf = new ByteArrayOutputStream(4 + other_secret.length + psk.length);
        TlsUtils.writeOpaque16(other_secret, buf);
        TlsUtils.writeOpaque16(psk, buf);

        Arrays.fill(psk, (byte)0);
        this.psk = null;

        return buf.toByteArray();
    }

    protected byte[] generateOtherSecret(int pskLength) throws IOException
    {
        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            if (dhAgreePrivateKey != null)
            {
                return TlsDHUtils.calculateDHBasicAgreement(dhAgreePublicKey, dhAgreePrivateKey);
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            if (ecAgreePrivateKey != null)
            {
                return TlsECCUtils.calculateECDHBasicAgreement(ecAgreePublicKey, ecAgreePrivateKey);
            }

            throw new TlsFatalAlert(AlertDescription.internal_error);
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

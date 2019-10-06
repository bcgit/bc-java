package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/**
 * (D)TLS PSK key exchange (RFC 4279).
 */
public class TlsPSKKeyExchange
    extends AbstractTlsKeyExchange
{
    private static int checkKeyExchange(int keyExchange)
    {
        switch (keyExchange)
        {
        case KeyExchangeAlgorithm.DHE_PSK:
        case KeyExchangeAlgorithm.ECDHE_PSK:
        case KeyExchangeAlgorithm.PSK:
        case KeyExchangeAlgorithm.RSA_PSK:
            return keyExchange;
        default:
            throw new IllegalArgumentException("unsupported key exchange algorithm");
        }
    }

    protected TlsPSKIdentity pskIdentity;
    protected TlsPSKIdentityManager pskIdentityManager;
    protected TlsDHGroupVerifier dhGroupVerifier;

    protected byte[] psk_identity_hint = null;
    protected byte[] psk = null;

    protected TlsDHConfig dhConfig;
    protected TlsECConfig ecConfig;
    protected TlsAgreement agreement;

    protected TlsCredentialedDecryptor serverCredentials = null;
    protected TlsCertificate serverCertificate;
    protected TlsSecret preMasterSecret;

    public TlsPSKKeyExchange(int keyExchange, TlsPSKIdentity pskIdentity, TlsDHGroupVerifier dhGroupVerifier)
    {
        this(keyExchange, pskIdentity, null, dhGroupVerifier, null, null);
    }

    public TlsPSKKeyExchange(int keyExchange, TlsPSKIdentityManager pskIdentityManager,
        TlsDHConfig dhConfig, TlsECConfig ecConfig)
    {
        this(keyExchange, null, pskIdentityManager, null, dhConfig, ecConfig);
    }

    private TlsPSKKeyExchange(int keyExchange, TlsPSKIdentity pskIdentity, TlsPSKIdentityManager pskIdentityManager,
        TlsDHGroupVerifier dhGroupVerifier, TlsDHConfig dhConfig, TlsECConfig ecConfig)
    {
        super(checkKeyExchange(keyExchange));

        this.pskIdentity = pskIdentity;
        this.pskIdentityManager = pskIdentityManager;
        this.dhGroupVerifier = dhGroupVerifier;
        this.dhConfig = dhConfig;
        this.ecConfig = ecConfig;
    }

    public void skipServerCredentials() throws IOException
    {
        if (keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    public void processServerCredentials(TlsCredentials serverCredentials) throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.RSA_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        this.serverCredentials = TlsUtils.requireDecryptorCredentials(serverCredentials);
    }

    public void processServerCertificate(Certificate serverCertificate) throws IOException
    {
        if (keyExchange != KeyExchangeAlgorithm.RSA_PSK)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        this.serverCertificate = serverCertificate.getCertificateAt(0).useInRole(ConnectionEnd.server, keyExchange);
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
            if (this.dhConfig == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsDHUtils.writeDHConfig(dhConfig, buf);

            this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

            generateEphemeralDH(buf);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            if (this.ecConfig == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsECCUtils.writeECConfig(ecConfig, buf);

            this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

            generateEphemeralECDH(buf);
        }

        return buf.toByteArray();
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
            this.dhConfig = TlsDHUtils.receiveDHConfig(context, dhGroupVerifier, input);

            byte[] y = TlsUtils.readOpaque16(input, 1);

            this.agreement = context.getCrypto().createDHDomain(dhConfig).createDH();

            processEphemeralDH(y);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            this.ecConfig = TlsECCUtils.receiveECDHConfig(context, input);

            byte[] point = TlsUtils.readOpaque8(input, 1);

            this.agreement = context.getCrypto().createECDomain(ecConfig).createECDH();

            processEphemeralECDH(point);
        }
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

        context.getSecurityParametersHandshake().pskIdentity = Arrays.clone(psk_identity);

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            generateEphemeralDH(output);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            generateEphemeralECDH(output);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            this.preMasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(context, serverCertificate, output);
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

        context.getSecurityParametersHandshake().pskIdentity = psk_identity;

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK)
        {
            byte[] y = TlsUtils.readOpaque16(input, 1);

            processEphemeralDH(y);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            byte[] point = TlsUtils.readOpaque8(input, 1);

            processEphemeralECDH(point);
        }
        else if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            byte[] encryptedPreMasterSecret = TlsUtils.readEncryptedPMS(context, input);

            this.preMasterSecret = serverCredentials.decrypt(new TlsCryptoParameters(context), encryptedPreMasterSecret);
        }
    }

    public TlsSecret generatePreMasterSecret() throws IOException
    {
        byte[] other_secret = generateOtherSecret(psk.length);

        ByteArrayOutputStream buf = new ByteArrayOutputStream(4 + other_secret.length + psk.length);
        TlsUtils.writeOpaque16(other_secret, buf);
        TlsUtils.writeOpaque16(psk, buf);

        Arrays.fill(psk, (byte)0);
        this.psk = null;

        return context.getCrypto().createSecret(buf.toByteArray());
    }

    protected void generateEphemeralDH(OutputStream output) throws IOException
    {
        byte[] y = agreement.generateEphemeral();
        TlsUtils.writeOpaque16(y, output);
    }

    protected void generateEphemeralECDH(OutputStream output) throws IOException
    {
        byte[] point = agreement.generateEphemeral();
        TlsUtils.writeOpaque8(point, output);
    }

    protected byte[] generateOtherSecret(int pskLength) throws IOException
    {
        if (this.keyExchange == KeyExchangeAlgorithm.PSK)
        {
            return new byte[pskLength];
        }

        if (this.keyExchange == KeyExchangeAlgorithm.DHE_PSK
            || this.keyExchange == KeyExchangeAlgorithm.ECDHE_PSK)
        {
            if (agreement != null)
            {
                return agreement.calculateSecret().extract();
            }
        }

        if (this.keyExchange == KeyExchangeAlgorithm.RSA_PSK)
        {
            if (preMasterSecret != null)
            {
                return this.preMasterSecret.extract();
            }
        }

        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void processEphemeralDH(byte[] y) throws IOException
    {
        this.agreement.receivePeerValue(y);
    }

    protected void processEphemeralECDH(byte[] point) throws IOException
    {
        TlsECCUtils.checkPointEncoding(ecConfig.getNamedGroup(), point);

        this.agreement.receivePeerValue(point);
    }
}

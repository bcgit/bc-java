package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Times;

abstract class AbstractTlsContext
    implements TlsContext
{
    private static long counter = Times.nanoTime();

    private synchronized static long nextCounterValue()
    {
        return ++counter;
    }

    private static TlsNonceGenerator createNonceGenerator(TlsCrypto crypto, int connectionEnd)
    {
        byte[] additionalSeedMaterial = new byte[16];
        Pack.longToBigEndian(nextCounterValue(), additionalSeedMaterial, 0);
        Pack.longToBigEndian(Times.nanoTime(), additionalSeedMaterial, 8);
        additionalSeedMaterial[0] &= 0x7F;
        additionalSeedMaterial[0] |= (byte)(connectionEnd << 7);

        return crypto.createNonceGenerator(additionalSeedMaterial);
    }

    private TlsCrypto crypto;
    private int connectionEnd;
    private TlsNonceGenerator nonceGenerator;
    private SecurityParameters securityParametersHandshake = null;
    private SecurityParameters securityParametersConnection = null;

    private ProtocolVersion[] clientSupportedVersions = null;
    private ProtocolVersion clientVersion = null;
    private ProtocolVersion rsaPreMasterSecretVersion = null;
    private TlsSession session = null;
    private Object userObject = null;

    AbstractTlsContext(TlsCrypto crypto, int connectionEnd)
    {
        this.crypto = crypto;
        this.connectionEnd = connectionEnd;
        this.nonceGenerator = createNonceGenerator(crypto, connectionEnd);
    }

    void handshakeBeginning(TlsPeer peer) throws IOException
    {
        synchronized (this)
        {
            if (null != securityParametersHandshake)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, "Handshake already started");
            }

            this.securityParametersHandshake = new SecurityParameters();
            this.securityParametersHandshake.entity = connectionEnd;

            if (null != securityParametersConnection)
            {
                securityParametersHandshake.renegotiating = true;
                securityParametersHandshake.secureRenegotiation = securityParametersConnection.isSecureRenegotiation();
                securityParametersHandshake.negotiatedVersion = securityParametersConnection.getNegotiatedVersion();
            }
        }

        peer.notifyHandshakeBeginning();
    }

    void handshakeComplete(TlsPeer peer, TlsSession session) throws IOException
    {
        synchronized (this)
        {
            if (null == securityParametersHandshake)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            this.session = session;
            this.securityParametersConnection = securityParametersHandshake;
            this.securityParametersHandshake = null;
        }

        peer.notifyHandshakeComplete();
    }

    synchronized boolean isConnected()
    {
        return null != securityParametersConnection;
    }

    synchronized boolean isHandshaking()
    {
        return null != securityParametersHandshake;
    }

    public TlsCrypto getCrypto()
    {
        return crypto;
    }

    public TlsNonceGenerator getNonceGenerator()
    {
        return nonceGenerator;
    }

    public synchronized SecurityParameters getSecurityParameters()
    {
        return null != securityParametersHandshake
            ?   securityParametersHandshake
            :   securityParametersConnection;
    }

    public synchronized SecurityParameters getSecurityParametersConnection()
    {
        return securityParametersConnection;
    }

    public synchronized SecurityParameters getSecurityParametersHandshake()
    {
        return securityParametersHandshake;
    }

    public ProtocolVersion[] getClientSupportedVersions()
    {
        return clientSupportedVersions;
    }

    void setClientSupportedVersions(ProtocolVersion[] clientSupportedVersions)
    {
        this.clientSupportedVersions = clientSupportedVersions;
    }

    public ProtocolVersion getClientVersion()
    {
        return clientVersion;
    }

    void setClientVersion(ProtocolVersion clientVersion)
    {
        this.clientVersion = clientVersion;
    }

    public ProtocolVersion getRSAPreMasterSecretVersion()
    {
        return rsaPreMasterSecretVersion;
    }

    void setRSAPreMasterSecretVersion(ProtocolVersion rsaPreMasterSecretVersion)
    {
        this.rsaPreMasterSecretVersion = rsaPreMasterSecretVersion;
    }

    public ProtocolVersion getServerVersion()
    {
        return getSecurityParameters().getNegotiatedVersion();
    }

    public TlsSession getResumableSession()
    {
        TlsSession session = getSession();
        if (session == null || !session.isResumable())
        {
            return null;
        }
        return session;
    }

    public TlsSession getSession()
    {
        return session;
    }

    public Object getUserObject()
    {
        return userObject;
    }

    public void setUserObject(Object userObject)
    {
        this.userObject = userObject;
    }

    public byte[] exportChannelBinding(int channelBinding)
    {
        SecurityParameters securityParameters = getSecurityParametersConnection();
        if (null == securityParameters)
        {
            throw new IllegalStateException("Export of channel bindings unavailable before handshake completion");
        }

        if (ChannelBinding.tls_exporter == channelBinding)
        {
            return exportKeyingMaterial("EXPORTER-Channel-Binding", TlsUtils.EMPTY_BYTES, 32);
        }

        if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
        {
            return null;
        }

        switch (channelBinding)
        {
        case ChannelBinding.tls_server_end_point:
        {
            byte[] tlsServerEndPoint = securityParameters.getTLSServerEndPoint();

            return TlsUtils.isNullOrEmpty(tlsServerEndPoint) ? null : Arrays.clone(tlsServerEndPoint);
        }

        case ChannelBinding.tls_unique:
        {
            return Arrays.clone(securityParameters.getTLSUnique());
        }

        case ChannelBinding.tls_unique_for_telnet:
        default:
            throw new UnsupportedOperationException();
        }
    }

    public byte[] exportEarlyKeyingMaterial(String asciiLabel, byte[] context, int length)
    {
        // TODO[tls13] Ensure early_exporter_master_secret is available suitably early!
        SecurityParameters sp = getSecurityParametersHandshake();
        if (null == sp)
        {
            throw new IllegalStateException("Export of early key material only available during handshake");
        }

        return exportKeyingMaterial13(checkEarlyExportSecret(sp.getEarlyExporterMasterSecret()),
            sp.getPRFCryptoHashAlgorithm(), asciiLabel, context, length);
    }

    public byte[] exportKeyingMaterial(String asciiLabel, byte[] context, int length)
    {
        /*
         * TODO[tls13] Introduce a TlsExporter interface? Avoid calculating (early) exporter
         * secret(s) unless the peer actually uses it.
         */
        SecurityParameters sp = getSecurityParametersConnection();
        if (null == sp)
        {
            throw new IllegalStateException("Export of key material unavailable before handshake completion");
        }
        if (!sp.isExtendedMasterSecret())
        {
            /*
             * RFC 7627 5.4. If a client or server chooses to continue with a full handshake without
             * the extended master secret extension, [..] the client or server MUST NOT export any
             * key material based on the new master secret for any subsequent application-level
             * authentication. In particular, it MUST disable [RFC5705] [..].
             */
            throw new IllegalStateException("Export of key material requires extended_master_secret");
        }

        if (TlsUtils.isTLSv13(sp.getNegotiatedVersion()))
        {
            return exportKeyingMaterial13(checkExportSecret(sp.getExporterMasterSecret()),
                sp.getPRFCryptoHashAlgorithm(), asciiLabel, context, length);
        }

        byte[] seed = TlsUtils.calculateExporterSeed(sp, context);

        return TlsUtils.PRF(sp, checkExportSecret(sp.getMasterSecret()), asciiLabel, seed, length).extract();
    }

    protected byte[] exportKeyingMaterial13(TlsSecret secret, int cryptoHashAlgorithm, String asciiLabel,
        byte[] context, int length)
    {
        if (null == context)
        {
            context = TlsUtils.EMPTY_BYTES;
        }
        else if (!TlsUtils.isValidUint16(context.length))
        {
            throw new IllegalArgumentException("'context' must have length less than 2^16 (or be null)");
        }

        try
        {
            TlsHash exporterHash = getCrypto().createHash(cryptoHashAlgorithm);
            byte[] emptyTranscriptHash = exporterHash.calculateHash();

            TlsSecret exporterSecret = TlsUtils.deriveSecret(getSecurityParametersConnection(), secret, asciiLabel,
                emptyTranscriptHash);

            byte[] exporterContext = emptyTranscriptHash;
            if (context.length > 0)
            {
                exporterHash.update(context, 0, context.length);
                exporterContext = exporterHash.calculateHash();
            }

            return TlsCryptoUtils
                .hkdfExpandLabel(exporterSecret, cryptoHashAlgorithm, "exporter", exporterContext, length).extract();
        }
        catch (IOException e)
        {
            // Should never happen
            throw new RuntimeException(e);
        }
    }

    protected TlsSecret checkEarlyExportSecret(TlsSecret secret)
    {
        if (null == secret)
        {
            // TODO[tls13] For symmetry with normal export, ideally available for notifyHandshakeBeginning() only
//            throw new IllegalStateException("Export of early key material only available from notifyHandshakeBeginning()");
            throw new IllegalStateException("Export of early key material not available for this handshake");
        }
        return secret;
    }

    protected TlsSecret checkExportSecret(TlsSecret secret)
    {
        if (null == secret)
        {
            throw new IllegalStateException("Export of key material only available from notifyHandshakeComplete()");
        }
        return secret;
    }
}

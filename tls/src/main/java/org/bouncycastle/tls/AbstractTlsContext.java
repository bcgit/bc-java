package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsNonceGenerator;
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

    private static TlsNonceGenerator createNonceGenerator(TlsCrypto crypto, SecurityParameters securityParameters)
    {
        byte[] additionalSeedMaterial = new byte[16];
        Pack.longToBigEndian(nextCounterValue(), additionalSeedMaterial, 0);
        Pack.longToBigEndian(Times.nanoTime(), additionalSeedMaterial, 8);
        additionalSeedMaterial[0] = (byte)securityParameters.entity;

        return crypto.createNonceGenerator(additionalSeedMaterial);
    }

    private TlsCrypto crypto;
    private TlsNonceGenerator nonceGenerator;
    private SecurityParameters securityParameters;

    private ProtocolVersion clientVersion = null;
    private ProtocolVersion serverVersion = null;
    private TlsSession session = null;
    private Object userObject = null;

    AbstractTlsContext(TlsCrypto crypto, SecurityParameters securityParameters)
    {
        this.crypto = crypto;
        this.nonceGenerator = createNonceGenerator(crypto, securityParameters);
        this.securityParameters = securityParameters;
    }

    public TlsCrypto getCrypto()
    {
        return crypto;
    }

    public TlsNonceGenerator getNonceGenerator()
    {
        return nonceGenerator;
    }

    public SecurityParameters getSecurityParameters()
    {
        return securityParameters;
    }

    public ProtocolVersion getClientVersion()
    {
        return clientVersion;
    }

    void setClientVersion(ProtocolVersion clientVersion)
    {
        this.clientVersion = clientVersion;
    }

    public ProtocolVersion getServerVersion()
    {
        return serverVersion;
    }

    void setServerVersion(ProtocolVersion serverVersion)
    {
        this.serverVersion = serverVersion;
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

    void setSession(TlsSession session)
    {
        this.session = session;
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
        switch (channelBinding)
        {
        case ChannelBinding.tls_unique:
        {
            byte[] tlsUnique = getSecurityParameters().getTLSUnique();
            if (tlsUnique == null)
            {
                throw new IllegalStateException("'tls-unique' channel binding unavailable before handshake completion");
            }
            return Arrays.clone(tlsUnique);
        }

        case ChannelBinding.tls_server_end_point:
        case ChannelBinding.tls_unique_for_telnet:
        default:
            throw new UnsupportedOperationException();
        }
    }

    public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length)
    {
        /*
         * TODO[session-hash]
         * 
         * draft-ietf-tls-session-hash-04 5.4. If a client or server chooses to continue with a full
         * handshake without the extended master secret extension, [..] the client or server MUST
         * NOT export any key material based on the new master secret for any subsequent
         * application-level authentication. In particular, it MUST disable [RFC5705] [..].
         */

        if (context_value != null && !TlsUtils.isValidUint16(context_value.length))
        {
            throw new IllegalArgumentException("'context_value' must have length less than 2^16 (or be null)");
        }

        SecurityParameters sp = getSecurityParameters();
        byte[] cr = sp.getClientRandom(), sr = sp.getServerRandom();

        int seedLength = cr.length + sr.length;
        if (context_value != null)
        {
            seedLength += (2 + context_value.length);
        }

        byte[] seed = new byte[seedLength];
        int seedPos = 0;

        System.arraycopy(cr, 0, seed, seedPos, cr.length);
        seedPos += cr.length;
        System.arraycopy(sr, 0, seed, seedPos, sr.length);
        seedPos += sr.length;
        if (context_value != null)
        {
            TlsUtils.writeUint16(context_value.length, seed, seedPos);
            seedPos += 2;
            System.arraycopy(context_value, 0, seed, seedPos, context_value.length);
            seedPos += context_value.length;
        }

        if (seedPos != seedLength)
        {
            throw new IllegalStateException("error in calculation of seed for export");
        }

        return TlsUtils.PRF(this, sp.getMasterSecret(), asciiLabel, seed, length).extract();
    }
}

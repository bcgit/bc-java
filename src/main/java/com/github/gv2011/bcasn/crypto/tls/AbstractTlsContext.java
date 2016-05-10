package com.github.gv2011.bcasn.crypto.tls;

import java.security.SecureRandom;

import com.github.gv2011.bcasn.crypto.Digest;
import com.github.gv2011.bcasn.crypto.prng.DigestRandomGenerator;
import com.github.gv2011.bcasn.crypto.prng.RandomGenerator;
import com.github.gv2011.bcasn.util.Times;

abstract class AbstractTlsContext
    implements TlsContext
{
    private static long counter = Times.nanoTime();

    private synchronized static long nextCounterValue()
    {
        return ++counter;
    }

    private RandomGenerator nonceRandom;
    private SecureRandom secureRandom;
    private SecurityParameters securityParameters;

    private ProtocolVersion clientVersion = null;
    private ProtocolVersion serverVersion = null;
    private TlsSession session = null;
    private Object userObject = null;

    AbstractTlsContext(SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        Digest d = TlsUtils.createHash(HashAlgorithm.sha256);
        byte[] seed = new byte[d.getDigestSize()];
        secureRandom.nextBytes(seed);

        this.nonceRandom = new DigestRandomGenerator(d);
        nonceRandom.addSeedMaterial(nextCounterValue());
        nonceRandom.addSeedMaterial(Times.nanoTime());
        nonceRandom.addSeedMaterial(seed);

        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
    }

    public RandomGenerator getNonceRandomGenerator()
    {
        return nonceRandom;
    }

    public SecureRandom getSecureRandom()
    {
        return secureRandom;
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
        return session;
    }

    void setResumableSession(TlsSession session)
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

        return TlsUtils.PRF(this, sp.getMasterSecret(), asciiLabel, seed, length);
    }
}

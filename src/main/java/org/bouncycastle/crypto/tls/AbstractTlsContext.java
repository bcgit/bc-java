package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

abstract class AbstractTlsContext
    implements TlsContext
{

    private SecureRandom secureRandom;
    private SecurityParameters securityParameters;

    private ProtocolVersion clientVersion = null;
    private ProtocolVersion serverVersion = null;
    private Object userObject = null;

    AbstractTlsContext(SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
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

    public void setClientVersion(ProtocolVersion clientVersion)
    {
        this.clientVersion = clientVersion;
    }

    public ProtocolVersion getServerVersion()
    {
        return serverVersion;
    }

    public void setServerVersion(ProtocolVersion serverVersion)
    {
        this.serverVersion = serverVersion;
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

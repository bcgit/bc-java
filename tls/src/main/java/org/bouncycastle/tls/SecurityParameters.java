package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;

public class SecurityParameters
{
    int entity = -1;
    int cipherSuite = -1;
    short compressionAlgorithm = CompressionMethod._null;
    short maxFragmentLength = -1;
    int prfAlgorithm = -1;
    int verifyDataLength = -1;
    TlsSecret masterSecret = null;
    byte[] clientRandom = null;
    byte[] serverRandom = null;
    byte[] sessionHash = null;
    byte[] pskIdentity = null;
    byte[] srpIdentity = null;
    boolean encryptThenMAC = false;
    boolean extendedMasterSecret = false;
    boolean truncatedHMac = false;

    void clear()
    {
        if (this.masterSecret != null)
        {
            this.masterSecret.destroy();
            this.masterSecret = null;
        }
    }

    /**
     * @return {@link ConnectionEnd}
     */
    public int getEntity()
    {
        return entity;
    }

    /**
     * @return {@link CipherSuite}
     */
    public int getCipherSuite()
    {
        return cipherSuite;
    }

    /**
     * @return {@link CompressionMethod}
     */
    public short getCompressionAlgorithm()
    {
        return compressionAlgorithm;
    }

    /**
     * @return {@link MaxFragmentLength}, or -1 if none
     */
    public short getMaxFragmentLength()
    {
        return maxFragmentLength;
    }

    /**
     * @return {@link PRFAlgorithm}
     */
    public int getPrfAlgorithm()
    {
        return prfAlgorithm;
    }

    public int getVerifyDataLength()
    {
        return verifyDataLength;
    }

    public TlsSecret getMasterSecret()
    {
        return masterSecret;
    }

    public byte[] getClientRandom()
    {
        return clientRandom;
    }

    public byte[] getServerRandom()
    {
        return serverRandom;
    }

    public byte[] getSessionHash()
    {
        return sessionHash;
    }

    /**
     * @deprecated Use {@link SecurityParameters#getPSKIdentity()}
     */
    public byte[] getPskIdentity()
    {
        return pskIdentity;
    }

    public byte[] getPSKIdentity()
    {
        return pskIdentity;
    }

    public byte[] getSRPIdentity()
    {
        return srpIdentity;
    }

    public boolean isEncryptThenMAC()
    {
        return encryptThenMAC;
    }

    public boolean isExtendedMasterSecret()
    {
        return extendedMasterSecret;
    }

    public boolean isTruncatedHMac()
    {
        return truncatedHMac;
    }
}

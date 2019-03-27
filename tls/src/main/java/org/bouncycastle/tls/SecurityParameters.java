package org.bouncycastle.tls;

import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Carrier class for general security parameters.
 */
public class SecurityParameters
{
    int entity = -1;
    boolean renegotiating = false;
    boolean secureRenegotiation = false;
    int cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;
    final short compressionAlgorithm = CompressionMethod._null;
    short maxFragmentLength = -1;
    int prfAlgorithm = -1;
    int verifyDataLength = -1;
    TlsSecret masterSecret = null;
    byte[] clientRandom = null;
    byte[] serverRandom = null;
    byte[] sessionHash = null;
    byte[] sessionID = null;
    byte[] pskIdentity = null;
    byte[] srpIdentity = null;
    byte[] tlsServerEndPoint = null;
    byte[] tlsUnique = null;
    boolean encryptThenMAC = false;
    boolean extendedMasterSecret = false;
    boolean extendedPadding = false;
    boolean truncatedHMac = false;
    ProtocolName applicationProtocol = null;
    boolean applicationProtocolSet = false;
    Vector clientServerNames = null;
    Vector clientSigAlgs = null;
    Vector clientSigAlgsCert = null;
    int[] clientSupportedGroups = null;
    int keyExchangeAlgorithm = -1;
    Certificate localCertificate = null;
    Certificate peerCertificate = null;
    ProtocolVersion negotiatedVersion = null;

    // TODO[tls-ops] Investigate whether we can handle verify data using TlsSecret
    byte[] localVerifyData = null;
    byte[] peerVerifyData = null;

    void clear()
    {
        sessionHash = null;
        sessionID = null;
        clientServerNames = null;
        clientSigAlgs = null;
        clientSigAlgsCert = null;
        clientSupportedGroups = null;

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

    public boolean isRenegotiating()
    {
        return renegotiating;
    }

    public boolean isSecureRenegotiation()
    {
        return secureRenegotiation;
    }

    /**
     * @return {@link CipherSuite}
     */
    public int getCipherSuite()
    {
        return cipherSuite;
    }

    public Vector getClientServerNames()
    {
        return clientServerNames;
    }

    public Vector getClientSigAlgs()
    {
        return clientSigAlgs;
    }

    public Vector getClientSigAlgsCert()
    {
        return clientSigAlgsCert;
    }

    public int[] getClientSupportedGroups()
    {
        return clientSupportedGroups;
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

    public byte[] getSessionID()
    {
        return sessionID;
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

    public byte[] getTLSServerEndPoint()
    {
        return tlsServerEndPoint;
    }

    public byte[] getTLSUnique()
    {
        return tlsUnique;
    }

    public boolean isEncryptThenMAC()
    {
        return encryptThenMAC;
    }

    public boolean isExtendedMasterSecret()
    {
        return extendedMasterSecret;
    }

    public boolean isExtendedPadding()
    {
        return extendedPadding;
    }

    public boolean isTruncatedHMac()
    {
        return truncatedHMac;
    }

    public ProtocolName getApplicationProtocol()
    {
        return applicationProtocol;
    }

    public boolean isApplicationProtocolSet()
    {
        return applicationProtocolSet;
    }

    public byte[] getLocalVerifyData()
    {
        return localVerifyData;
    }

    public byte[] getPeerVerifyData()
    {
        return peerVerifyData;
    }

    public int getKeyExchangeAlgorithm()
    {
        return keyExchangeAlgorithm;
    }

    public Certificate getLocalCertificate()
    {
        return localCertificate;
    }

    public Certificate getPeerCertificate()
    {
        return peerCertificate;
    }

    public ProtocolVersion getNegotiatedVersion()
    {
        return negotiatedVersion;
    }
}

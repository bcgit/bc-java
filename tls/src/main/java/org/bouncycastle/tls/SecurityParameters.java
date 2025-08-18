package org.bouncycastle.tls;

import java.util.Vector;

import org.bouncycastle.tls.crypto.CryptoHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Carrier class for general security parameters.
 */
public class SecurityParameters
{
    int entity = -1;
    boolean resumedSession = false;
    boolean renegotiating = false;
    boolean secureRenegotiation = false;
    int cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;
    short maxFragmentLength = -1;
    int prfAlgorithm = -1;
    int prfCryptoHashAlgorithm = -1;
    int prfHashLength = -1;
    int verifyDataLength = -1;
    TlsSecret baseKeyClient = null;
    TlsSecret baseKeyServer = null;
    TlsSecret earlyExporterMasterSecret = null;
    TlsSecret earlySecret = null;
    TlsSecret exporterMasterSecret = null;
    TlsSecret handshakeSecret = null;
    TlsSecret masterSecret = null;
    TlsSecret trafficSecretClient = null;
    TlsSecret trafficSecretServer = null;
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
    short[] clientCertTypes = null;
    Vector clientServerNames = null;
    Vector clientSigAlgs = null;
    Vector clientSigAlgsCert = null;
    int[] clientSupportedGroups = null;
    Vector serverSigAlgs = null;
    Vector serverSigAlgsCert = null;
    int[] serverSupportedGroups = null;
    int keyExchangeAlgorithm = -1;
    Certificate localCertificate = null;
    Certificate peerCertificate = null;
    ProtocolVersion negotiatedVersion = null;
    int statusRequestVersion = 0;
    short clientCertificateType = CertificateType.X509;
    short serverCertificateType = CertificateType.X509;

    // TODO[tls-ops] Investigate whether we can handle verify data using TlsSecret
    byte[] localVerifyData = null;
    byte[] peerVerifyData = null;

    /** Connection ID we use during communication to the peer. */
    byte[] connectionIDLocal;
    /** Connection ID our peer uses for communication to us. */
    byte[] connectionIDPeer;

    void clear()
    {
        this.sessionHash = null;
        this.sessionID = null;
        this.clientCertTypes = null;
        this.clientServerNames = null;
        this.clientSigAlgs = null;
        this.clientSigAlgsCert = null;
        this.clientSupportedGroups = null;
        this.serverSigAlgs = null;
        this.serverSigAlgsCert = null;
        this.serverSupportedGroups = null;
        this.statusRequestVersion = 0;

        this.baseKeyClient = clearSecret(baseKeyClient);
        this.baseKeyServer = clearSecret(baseKeyServer);
        this.earlyExporterMasterSecret = clearSecret(earlyExporterMasterSecret);
        this.earlySecret = clearSecret(earlySecret);
        this.exporterMasterSecret = clearSecret(exporterMasterSecret);
        this.handshakeSecret = clearSecret(handshakeSecret);
        this.masterSecret = clearSecret(masterSecret);
    }

    /**
     * @return {@link ConnectionEnd}
     */
    public int getEntity()
    {
        return entity;
    }

    public boolean isResumedSession()
    {
        return resumedSession;
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

    public short[] getClientCertTypes()
    {
        return clientCertTypes;
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

    public byte[] getConnectionIDLocal()
    {
        return connectionIDLocal;
    }

    public byte[] getConnectionIDPeer()
    {
        return connectionIDPeer;
    }

    public Vector getServerSigAlgs()
    {
        return serverSigAlgs;
    }

    public Vector getServerSigAlgsCert()
    {
        return serverSigAlgsCert;
    }

    public int[] getServerSupportedGroups()
    {
        return serverSupportedGroups;
    }

    /**
     * @return {@link CompressionMethod}
     * 
     * @deprecated Will be removed. Use constant CompressionMethod._null instead.
     */
    @Deprecated
    @SuppressWarnings("InlineMeSuggester")
    public short getCompressionAlgorithm()
    {
        return CompressionMethod._null;
    }

    /**
     * @return {@link MaxFragmentLength}, or -1 if none
     */
    public short getMaxFragmentLength()
    {
        return maxFragmentLength;
    }

    /**
     * @deprecated Use {@link #getPRFAlgorithm()} instead.
     */
    @Deprecated
    public int getPrfAlgorithm()
    {
        return prfAlgorithm;
    }

    /**
     * @return {@link PRFAlgorithm}
     */
    public int getPRFAlgorithm()
    {
        return prfAlgorithm;
    }

    /**
     * @return {@link CryptoHashAlgorithm} for the current {@link PRFAlgorithm}
     */
    public int getPRFCryptoHashAlgorithm()
    {
        return prfCryptoHashAlgorithm;
    }

    public int getPRFHashLength()
    {
        return prfHashLength;
    }

    public int getVerifyDataLength()
    {
        return verifyDataLength;
    }

    public TlsSecret getBaseKeyClient()
    {
        return baseKeyClient;
    }

    public TlsSecret getBaseKeyServer()
    {
        return baseKeyServer;
    }

    public TlsSecret getEarlyExporterMasterSecret()
    {
        return earlyExporterMasterSecret;
    }

    public TlsSecret getEarlySecret()
    {
        return earlySecret;
    }

    public TlsSecret getExporterMasterSecret()
    {
        return exporterMasterSecret;
    }

    public TlsSecret getHandshakeSecret()
    {
        return handshakeSecret;
    }

    public TlsSecret getMasterSecret()
    {
        return masterSecret;
    }

    public TlsSecret getTrafficSecretClient()
    {
        return trafficSecretClient;
    }

    public TlsSecret getTrafficSecretServer()
    {
        return trafficSecretServer;
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

    public int getStatusRequestVersion()
    {
        return statusRequestVersion;
    }

    public short getClientCertificateType()
    {
        return clientCertificateType;
    }

    public short getServerCertificateType()
    {
        return serverCertificateType;
    }

    private static TlsSecret clearSecret(TlsSecret secret)
    {
        if (null != secret)
        {
            secret.destroy();
        }
        return null;
    }
}

package org.bouncycastle.crypto.split.message;

import java.util.Date;

import org.bouncycastle.crypto.split.enumeration.KMIPAttestationType;

public class KMIPResponseHeader
{
    private KMIPProtocolVersion protocolVersion;   // Required
    private Date timeStamp;                    // Required
    private KMIPNonce nonce;                      // Optional
    private byte[] serverHashedPassword;       // Required if Hashed Password is used
    private KMIPAttestationType[] attestationTypes;     // Optional, may be repeated
    private String clientCorrelationValue;     // Optional
    private String serverCorrelationValue;     // Optional
    private int batchCount;                    // Required

    public KMIPResponseHeader(KMIPProtocolVersion protocolVersion, Date timeStamp, int batchCount)
    {
        this.protocolVersion = protocolVersion;
        this.timeStamp = timeStamp;
        this.batchCount = batchCount;
    }

    // Getters and Setters for each field
    public KMIPProtocolVersion getProtocolVersion()
    {
        return protocolVersion;
    }

    public void setProtocolVersion(KMIPProtocolVersion protocolVersion)
    {
        this.protocolVersion = protocolVersion;
    }

    public Date getTimeStamp()
    {
        return timeStamp;
    }

    public void setTimeStamp(Date timeStamp)
    {
        this.timeStamp = timeStamp;
    }

    public KMIPNonce getNonce()
    {
        return nonce;
    }

    public void setNonce(KMIPNonce nonce)
    {
        this.nonce = nonce;
    }

    public byte[] getServerHashedPassword()
    {
        return serverHashedPassword;
    }

    public void setServerHashedPassword(byte[] serverHashedPassword)
    {
        this.serverHashedPassword = serverHashedPassword;
    }

    public KMIPAttestationType[] getAttestationTypes()
    {
        return attestationTypes;
    }

    public void setAttestationTypes(KMIPAttestationType[] attestationTypes)
    {
        this.attestationTypes = attestationTypes;
    }

    public String getClientCorrelationValue()
    {
        return clientCorrelationValue;
    }

    public void setClientCorrelationValue(String clientCorrelationValue)
    {
        this.clientCorrelationValue = clientCorrelationValue;
    }

    public String getServerCorrelationValue()
    {
        return serverCorrelationValue;
    }

    public void setServerCorrelationValue(String serverCorrelationValue)
    {
        this.serverCorrelationValue = serverCorrelationValue;
    }

    public int getBatchCount()
    {
        return batchCount;
    }

    public void setBatchCount(int batchCount)
    {
        this.batchCount = batchCount;
    }

    // You may add validation methods for required/optional fields if needed.
}

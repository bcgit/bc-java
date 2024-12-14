package org.bouncycastle.kmip.wire.message;

import java.util.Date;

import org.bouncycastle.kmip.wire.enumeration.KMIPAttestationType;

public abstract class KMIPHeader
{
    protected KMIPProtocolVersion protocolVersion;
    protected int batchCount;
    protected String clientCorrelationValue;  // Optional
    protected String serverCorrelationValue;  // Optional
    protected Date timeStamp;  // Optional
    protected KMIPAttestationType[] attestationType;  // Optional, repeated

    public KMIPHeader(KMIPProtocolVersion protocolVersion, int batchCount)
    {
        this.protocolVersion = protocolVersion;
        this.batchCount = batchCount;
    }

    public KMIPProtocolVersion getProtocolVersion()
    {
        return protocolVersion;
    }

    public void setProtocolVersion(KMIPProtocolVersion protocolVersion)
    {
        this.protocolVersion = protocolVersion;
    }

    public int getBatchCount()
    {
        return batchCount;
    }

    public void setBatchCount(int batchCount)
    {
        this.batchCount = batchCount;
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

    public Date getTimeStamp()
    {
        return timeStamp;
    }

    public void setTimeStamp(Date timeStamp)
    {
        this.timeStamp = timeStamp;
    }

    public KMIPAttestationType[] getAttestationType()
    {
        return attestationType;
    }

    public void setAttestationType(KMIPAttestationType[] attestationType)
    {
        this.attestationType = attestationType;
    }
}

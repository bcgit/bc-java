package org.bouncycastle.crypto.split.message;

import java.util.Date;

import org.bouncycastle.crypto.split.enumeration.KMIPAttestationType;

/**
 * This class represents the Request Header for a protocol message.
 * It includes mandatory and optional fields to control various aspects
 * of the request being sent.
 */
public class KMIPRequestHeader
{

    private final KMIPProtocolVersion protocolVersion;  // Required field
    private final int batchCount;  // Required field
    private int maximumResponseSize;  // Optional
    private String clientCorrelationValue;  // Optional
    private String serverCorrelationValue;  // Optional
    private boolean asynchronousIndicator;  // Optional
    private boolean attestationCapableIndicator;  // Optional
    private KMIPAttestationType[] attestationType;  // Optional, repeated
    private String authentication;  // Optional
    private String batchErrorContinuationOption;  // Optional, default "Stop"
    private boolean batchOrderOption;  // Optional, default "True"
    private Date timeStamp;  // Optional

    /**
     * Constructor to initialize required fields.
     *
     * @param protocolVersion The version of the protocol (required).
     * @param batchCount      The count of the batch (required).
     */
    public KMIPRequestHeader(KMIPProtocolVersion protocolVersion, int batchCount)
    {
        this.protocolVersion = protocolVersion;
        this.batchCount = batchCount;
        this.batchErrorContinuationOption = "Stop";  // Default value
        this.batchOrderOption = true;  // Default value
    }

    // Getters and Setters for optional fields

    public KMIPProtocolVersion getProtocolVersion()
    {
        return protocolVersion;
    }

    public int getBatchCount()
    {
        return batchCount;
    }

    public int getMaximumResponseSize()
    {
        return maximumResponseSize;
    }

    public void setMaximumResponseSize(int maximumResponseSize)
    {
        this.maximumResponseSize = maximumResponseSize;
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

    public boolean getAsynchronousIndicator()
    {
        return asynchronousIndicator;
    }

    public void setAsynchronousIndicator(boolean asynchronousIndicator)
    {
        this.asynchronousIndicator = asynchronousIndicator;
    }

    public boolean getAttestationCapableIndicator()
    {
        return attestationCapableIndicator;
    }

    public void setAttestationCapableIndicator(boolean attestationCapableIndicator)
    {
        this.attestationCapableIndicator = attestationCapableIndicator;
    }

    public KMIPAttestationType[] getAttestationType()
    {
        return attestationType;
    }

    public void setAttestationType(KMIPAttestationType[] attestationType)
    {
        this.attestationType = attestationType;
    }

    public String getAuthentication()
    {
        return authentication;
    }

    public void setAuthentication(String authentication)
    {
        this.authentication = authentication;
    }

    public String getBatchErrorContinuationOption()
    {
        return batchErrorContinuationOption;
    }

    public void setBatchErrorContinuationOption(String batchErrorContinuationOption)
    {
        this.batchErrorContinuationOption = batchErrorContinuationOption;
    }

    public boolean getBatchOrderOption()
    {
        return batchOrderOption;
    }

    public void setBatchOrderOption(boolean batchOrderOption)
    {
        this.batchOrderOption = batchOrderOption;
    }

    public Date getTimeStamp()
    {
        return timeStamp;
    }

    public void setTimeStamp(Date timeStamp)
    {
        this.timeStamp = timeStamp;
    }
}

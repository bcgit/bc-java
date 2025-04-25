package org.bouncycastle.kmip.wire.message;

/**
 * This class represents the Request Header for a protocol message.
 * It includes mandatory and optional fields to control various aspects
 * of the request being sent.
 */
public class KMIPRequestHeader
    extends KMIPHeader
{
    private int maximumResponseSize;  // Optional
    private boolean asynchronousIndicator;  // Optional
    private boolean attestationCapableIndicator;  // Optional
    private String authentication;  // Optional
    private String batchErrorContinuationOption;  // Optional, default "Stop"
    private boolean batchOrderOption;  // Optional, default "True"

    /**
     * Constructor to initialize required fields.
     *
     * @param protocolVersion The version of the protocol (required).
     * @param batchCount      The count of the batch (required).
     */
    public KMIPRequestHeader(KMIPProtocolVersion protocolVersion, int batchCount)
    {
        super(protocolVersion, batchCount);
        this.batchErrorContinuationOption = "Stop";  // Default value
        this.batchOrderOption = true;  // Default value
    }

    public int getMaximumResponseSize()
    {
        return maximumResponseSize;
    }

    public void setMaximumResponseSize(int maximumResponseSize)
    {
        this.maximumResponseSize = maximumResponseSize;
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
}

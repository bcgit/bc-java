package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.enumeration.KMIPOperation;

public class KMIPRequestBatchItem
    extends KMIPBatchItem
{
    private boolean ephemeral;     // Indicates if the data output should not be returned
    // 9.21 This is an OPTIONAL field contained in a request, and is used for correlation between requests and
    //responses. If a request has a Unique Batch Item ID, then responses to that request SHALL have the
    //same Unique Batch Item ID.
    private byte[] uniqueBatchItemId; // Optional unique ID for the batch item
    private KMIPRequestPayload requestPayload; // Required request payload
    private KMIPMessageExtension[] messageExtensions; // Optional message extensions

    // Constructor for mandatory fields
    public KMIPRequestBatchItem(KMIPOperation operation, KMIPRequestPayload requestPayload)
    {
        super(operation);
        this.requestPayload = requestPayload;
        this.ephemeral = false; // Default to false
        this.messageExtensions = new KMIPMessageExtension[0]; // Initialize list for message extensions
    }

    public boolean getEphemeral()
    {
        return ephemeral;
    }

    public void setEphemeral(boolean ephemeral)
    {
        this.ephemeral = ephemeral;
    }

    public byte[] getUniqueBatchItemId()
    {
        return uniqueBatchItemId;
    }

    public void setUniqueBatchItemId(byte[] uniqueBatchItemId)
    {
        this.uniqueBatchItemId = uniqueBatchItemId;
    }

    public KMIPRequestPayload getRequestPayload()
    {
        return requestPayload;
    }

    public void setRequestPayload(KMIPRequestPayload requestPayload)
    {
        this.requestPayload = requestPayload;
    }

    public KMIPMessageExtension[] getMessageExtensions()
    {
        return messageExtensions;
    }

    public void setMessageExtension(KMIPMessageExtension[] extensions)
    {
        this.messageExtensions = extensions; // Add extension to the list
    }
}

package org.bouncycastle.kmip.wire.message;

public class KMIPResponseMessage
    extends KMIPMessage
{
    private KMIPResponseHeader responseHeader; // Header of the response
    private KMIPBatchItem[] batchItems;  // List of batch items

    public KMIPResponseMessage(KMIPResponseHeader responseHeader, KMIPBatchItem[] batchItems)
    {
        this.responseHeader = responseHeader;
        this.batchItems = batchItems; // Initialize the list
    }

    public KMIPResponseHeader getResponseHeader()
    {
        return responseHeader;
    }

    public KMIPBatchItem[] getBatchItems()
    {
        return batchItems;
    }
}


package org.bouncycastle.kmip.wire.message;

public class KMIPRequestMessage
    extends KMIPMessage
{
    private KMIPRequestHeader requestHeader; // Header of the request
    private KMIPBatchItem[] batchItems;  // List of batch items

    public KMIPRequestMessage(KMIPRequestHeader requestHeader, KMIPBatchItem[] batchItems)
    {
        this.requestHeader = requestHeader;
        this.batchItems = batchItems; // Initialize the list
    }

    public KMIPRequestHeader getRequestHeader()
    {
        return requestHeader;
    }

    public KMIPBatchItem[] getBatchItems()
    {
        return batchItems;
    }
}

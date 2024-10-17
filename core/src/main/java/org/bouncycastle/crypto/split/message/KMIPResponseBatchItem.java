package org.bouncycastle.crypto.split.message;

import org.bouncycastle.crypto.split.enumeration.KMIPOperation;
import org.bouncycastle.crypto.split.enumeration.KMIPResultReason;
import org.bouncycastle.crypto.split.enumeration.KMIPResultStatus;

public class KMIPResponseBatchItem
    extends KMIPBatchItem
{
    private KMIPOperation operation;           // Operation, if specified in the Request Batch Item
    private String uniqueBatchItemID;   // Unique Batch Item ID, optional
    private KMIPResultStatus resultStatus;  // Result Status
    private KMIPResultReason resultReason;        // Result Reason, required if Result Status is Failure
    private String resultMessage;       // Optional, unless Result Status is Pending or Success
    private String asyncCorrelationValue; // Required if Result Status is Pending
    private KMIPResponsePayload responsePayload; // Structure, contents depend on the Operation
    private KMIPMessageExtension messageExtension; // Optional Message Extension

    // Constructor
    public KMIPResponseBatchItem(KMIPOperation operation, KMIPResultStatus resultStatus,
                                 KMIPResponsePayload responsePayload)
    {
        this.operation = operation;
        this.resultStatus = resultStatus;
        this.responsePayload = responsePayload;
    }

    public KMIPOperation getOperation()
    {
        return operation;
    }

    public void setOperation(KMIPOperation operation)
    {
        this.operation = operation;
    }

    public String getUniqueBatchItemID()
    {
        return uniqueBatchItemID;
    }

    public void setUniqueBatchItemID(String uniqueBatchItemID)
    {
        this.uniqueBatchItemID = uniqueBatchItemID;
    }

    public KMIPResultStatus getResultStatus()
    {
        return resultStatus;
    }

    public void setResultStatus(KMIPResultStatus resultStatus)
    {
        this.resultStatus = resultStatus;
    }

    public KMIPResultReason getResultReason()
    {
        return resultReason;
    }

    public void setResultReason(KMIPResultReason resultReason)
    {
        this.resultReason = resultReason;
    }

    public String getResultMessage()
    {
        return resultMessage;
    }

    public void setResultMessage(String resultMessage)
    {
        this.resultMessage = resultMessage;
    }

    public String getAsyncCorrelationValue()
    {
        return asyncCorrelationValue;
    }

    public void setAsyncCorrelationValue(String asyncCorrelationValue)
    {
        this.asyncCorrelationValue = asyncCorrelationValue;
    }

    public KMIPResponsePayload getResponsePayload()
    {
        return responsePayload;
    }

    public void setResponsePayload(KMIPResponsePayload responsePayload)
    {
        this.responsePayload = responsePayload;
    }

    public KMIPMessageExtension getMessageExtension()
    {
        return messageExtension;
    }

    public void setMessageExtension(KMIPMessageExtension messageExtension)
    {
        this.messageExtension = messageExtension;
    }
}


package org.bouncycastle.kmip.wire.message;

import org.bouncycastle.kmip.wire.enumeration.KMIPOperation;

public abstract class KMIPBatchItem
{
    protected KMIPOperation operation;           // Operation, if specified in the Batch Item

    public KMIPBatchItem(KMIPOperation operation)
    {
        this.operation = operation;
    }

    public KMIPOperation getOperation()
    {
        return operation;
    }

    public void setOperation(KMIPOperation operation)
    {
        this.operation = operation;
    }
}

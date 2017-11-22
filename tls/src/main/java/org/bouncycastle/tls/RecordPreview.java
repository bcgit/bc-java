package org.bouncycastle.tls;

public final class RecordPreview
{
    private final int recordSize;
    private final int applicationDataLimit;

    static RecordPreview combine(RecordPreview a, RecordPreview b)
    {
        return new RecordPreview(
            a.getRecordSize() + b.getRecordSize(),
            a.getApplicationDataLimit() + b.getApplicationDataLimit());
    }

    RecordPreview(int recordSize, int applicationDataLimit)
    {
        this.recordSize = recordSize;
        this.applicationDataLimit = applicationDataLimit;
    }
    
    public int getApplicationDataLimit()
    {
        return applicationDataLimit;
    }

    public int getRecordSize()
    {
        return recordSize;
    }
}

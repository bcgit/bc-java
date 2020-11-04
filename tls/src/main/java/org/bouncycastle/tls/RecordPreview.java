package org.bouncycastle.tls;

public final class RecordPreview
{
    private final int recordSize;
    private final int contentLimit;

    static RecordPreview combineAppData(RecordPreview a, RecordPreview b)
    {
        return new RecordPreview(a.getRecordSize() + b.getRecordSize(), a.getContentLimit() + b.getContentLimit());
    }

    static RecordPreview extendRecordSize(RecordPreview a, int recordSize)
    {
        return new RecordPreview(a.getRecordSize() + recordSize, a.getContentLimit());
    }

    RecordPreview(int recordSize, int contentLimit)
    {
        this.recordSize = recordSize;
        this.contentLimit = contentLimit;
    }

    /** @deprecated Use {@link #getContentLimit} instead */
    public int getApplicationDataLimit()
    {
        return contentLimit;
    }

    public int getContentLimit()
    {
        return contentLimit;
    }

    public int getRecordSize()
    {
        return recordSize;
    }
}

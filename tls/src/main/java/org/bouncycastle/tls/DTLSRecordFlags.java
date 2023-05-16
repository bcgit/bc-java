package org.bouncycastle.tls;

public abstract class DTLSRecordFlags
{
    public static final int NONE = 0;

    /** The record is newer (by epoch and sequence number) than any record received previously. */
    public static final int IS_NEWEST = 1;

    /** The record includes the (valid) connection ID (RFC 9146) for this connection. */
    public static final int USES_CONNECTION_ID = 2;
}

package org.bouncycastle.tls;

public interface DTLSRecordCallback
{
    /**
     * Called when a record is accepted by the record layer.
     * @param flags see {@link DTLSRecordFlags} for constants.
     */
    void recordAccepted(int flags);
}

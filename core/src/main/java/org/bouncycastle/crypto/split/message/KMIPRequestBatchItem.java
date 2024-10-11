package org.bouncycastle.crypto.split.message;

import org.bouncycastle.crypto.split.KMIPOperation;

public class KMIPRequestBatchItem {
    private KMIPOperation operation;  // Required operation for the batch item
    private Boolean ephemeral;     // Indicates if the data output should not be returned
    private String uniqueBatchItemId; // Optional unique ID for the batch item
    private KMIPRequestPayload requestPayload; // Required request payload
    private String[] messageExtensions; // Optional message extensions

    // Constructor for mandatory fields
    public KMIPRequestBatchItem(KMIPOperation operation, KMIPRequestPayload requestPayload) {
        this.operation = operation;
        this.requestPayload = requestPayload;
        this.ephemeral = false; // Default to false
        this.messageExtensions = new String[0]; // Initialize list for message extensions
    }

    public KMIPOperation getOperation() {
        return operation;
    }

    public void setOperation(KMIPOperation operation) {
        this.operation = operation;
    }

    public Boolean getEphemeral() {
        return ephemeral;
    }

    public void setEphemeral(Boolean ephemeral) {
        this.ephemeral = ephemeral;
    }

    public String getUniqueBatchItemId() {
        return uniqueBatchItemId;
    }

    public void setUniqueBatchItemId(String uniqueBatchItemId) {
        this.uniqueBatchItemId = uniqueBatchItemId;
    }

    public KMIPRequestPayload getRequestPayload() {
        return requestPayload;
    }

    public void setRequestPayload(KMIPRequestPayload requestPayload) {
        this.requestPayload = requestPayload;
    }

    public String[] getMessageExtensions() {
        return messageExtensions;
    }

//    public void addMessageExtension(String extension) {
//        this.messageExtensions.add(extension); // Add extension to the list
//    }

    @Override
    public String toString() {
        return "BatchItem{" +
            "operation=" + operation +
            ", ephemeral=" + ephemeral +
            ", uniqueBatchItemId='" + uniqueBatchItemId + '\'' +
            ", requestPayload=" + requestPayload +
            ", messageExtensions=" + messageExtensions +
            '}';
    }
}
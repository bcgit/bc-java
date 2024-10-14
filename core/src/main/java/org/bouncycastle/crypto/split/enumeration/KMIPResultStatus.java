package org.bouncycastle.crypto.split.enumeration;

/**
 * Enumeration representing the possible result statuses for an operation.
 */
public enum KMIPResultStatus {

    SUCCESS(0),              // Operation was successful
    OPERATION_FAILED(1),     // Operation failed
    OPERATION_PENDING(2),    // Operation is pending
    OPERATION_UNDONE(3);     // Operation was undone

    private final int value;

    /**
     * Constructor for ResultStatus enum.
     *
     * @param value The integer value representing the status code.
     */
    KMIPResultStatus(int value) {
        this.value = value;
    }

    /**
     * Gets the integer value associated with the result status.
     *
     * @return The integer value of the result status.
     */
    public int getValue() {
        return value;
    }

    /**
     * Retrieves a ResultStatus based on the provided integer value.
     *
     * @param value The integer value of the result status.
     * @return The corresponding ResultStatus enum.
     * @throws IllegalArgumentException if the value does not match any result status.
     */
    public static KMIPResultStatus fromValue(int value) {
        for (KMIPResultStatus status : KMIPResultStatus.values()) {
            if (status.getValue() == value) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown result status value: " + Integer.toHexString(value));
    }

    @Override
    public String toString() {
        return name() + "(0x" + Integer.toHexString(value) + ")";
    }
}


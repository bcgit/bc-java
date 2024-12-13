package org.bouncycastle.kmip.wire.enumeration;

/**
 * Enumeration representing the possible result statuses for an operation.
 */
public enum KMIPResultStatus
    implements KMIPEnumeration
{
    Success(0x00000000),             // Success
    OperationFailed(0x00000001),     // Operation Failed
    OperationPending(0x00000002),    // Operation Pending
    OperationUndone(0x00000003);     // Operation Undone

    private final int value;

    /**
     * Constructor for ResultStatus enum.
     *
     * @param value The integer value representing the status code.
     */
    KMIPResultStatus(int value)
    {
        this.value = value;
    }

    /**
     * Gets the integer value associated with the result status.
     *
     * @return The integer value of the result status.
     */
    public int getValue()
    {
        return value;
    }

    /**
     * Retrieves a ResultStatus based on the provided integer value.
     *
     * @param value The integer value of the result status.
     * @return The corresponding ResultStatus enum.
     * @throws IllegalArgumentException if the value does not match any result status.
     */
    public static KMIPResultStatus fromValue(int value)
    {
        for (KMIPResultStatus status : KMIPResultStatus.values())
        {
            if (status.getValue() == value)
            {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown result status value: " + Integer.toHexString(value));
    }

    @Override
    public String toString()
    {
        return name() + "(0x" + Integer.toHexString(value) + ")";
    }
}


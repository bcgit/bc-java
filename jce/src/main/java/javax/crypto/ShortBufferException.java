package javax.crypto;

import java.security.GeneralSecurityException;

/**
 * This exception is thrown when an output buffer provided by the user
 * is too short to hold the operation result.
 */
public class ShortBufferException
    extends GeneralSecurityException
{
    private static final long serialVersionUID = 8427718640832943747L;

    /**
     * Constructs a ShortBufferException with no detail
     * message. A detail message is a String that describes this
     * particular exception.
     */
    public ShortBufferException()
    {
    }

    /**
     * Constructs a ShortBufferException with the specified
     * detail message. A detail message is a String that describes
     * this particular exception, which may, for example, specify which
     * algorithm is not available.
     *
     * @param msg the detail message.
     */
    public ShortBufferException(
        String  msg)
    {
        super(msg);
    }
}

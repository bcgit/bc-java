package javax.crypto;

import java.security.GeneralSecurityException;

/**
 * This exception is thrown when a particular padding mechanism is
 * requested but is not available in the environment.
 */
public class NoSuchPaddingException
    extends GeneralSecurityException
{
    private static final long serialVersionUID = -4572885201200175466L;

    /**
     * Constructs a NoSuchPaddingException with no detail
     * message. A detail message is a String that describes this
     * particular exception.
     */
    public NoSuchPaddingException()
    {
    }

    /**
     * Constructs a NoSuchPaddingException with the specified
     * detail message. A detail message is a String that describes
     * this particular exception, which may, for example, specify which
     * algorithm is not available.
     *
     * @param msg - the detail message.
     */
    public NoSuchPaddingException(
        String  msg)
    {
        super(msg);
    }
}

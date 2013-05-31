package javax.crypto;

import java.security.GeneralSecurityException;

/**
 * This exception is thrown when the length of data provided to a block
 * cipher is incorrect, i.e., does not match the block size of the cipher.
 *
 */
public class IllegalBlockSizeException
    extends GeneralSecurityException
{
    private static final long serialVersionUID = -1965144811953540392L;

    /**
     * Constructs an IllegalBlockSizeException with no detail message.
     * (A detail message is a String that describes this particular
     * exception.)
     */
    public IllegalBlockSizeException()
    {
    }

    /**
     * Constructs an IllegalBlockSizeException with the specified
     * detail message. (A detail message is a String that describes
     * this particular exception.)
     *
     * @param msg the detail message.
     */
    public IllegalBlockSizeException(
        String  msg)
    {
        super(msg);
    }
}

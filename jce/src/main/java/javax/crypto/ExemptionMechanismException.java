package javax.crypto;

import java.security.GeneralSecurityException;

/**
 * This is the generic ExemptionMechanism exception.
 *
 */
public class ExemptionMechanismException
    extends GeneralSecurityException
{
    private static final long serialVersionUID = 1572699429277957109L;

    /**
     * Constructs a ExemptionMechanismException with no detailed message.
     * (A detailed message is a String that describes this particular exception.)
     */
    public ExemptionMechanismException()
    {
    }

    /**
     * Constructs a ExemptionMechanismException with the specified
     * detailed message. (A detailed message is a String that describes
     * this particular exception.)
     *
     * @param msg the detailed message.
     */
    public ExemptionMechanismException(
        String  msg)
    {
        super(msg);
    }
}

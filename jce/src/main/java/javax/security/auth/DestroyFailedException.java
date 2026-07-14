package javax.security.auth;

// NOTE: jdk1.3 clean-room backport of the Java 1.4 javax.security.auth.DestroyFailedException,
// absent from the JDK 1.3.1 rt.jar. Mirrors the real API: extends Exception, no-arg and
// (String) constructors. See Destroyable.
public class DestroyFailedException
    extends Exception
{
    public DestroyFailedException()
    {
        super();
    }

    public DestroyFailedException(String msg)
    {
        super(msg);
    }
}

package javax.security.auth;

// NOTE: jdk1.3 clean-room backport. javax.security.auth.Destroyable arrived in Java 1.4 and is
// absent from the JDK 1.3.1 rt.jar, so the ~30 BC key classes that implement it will not compile
// on 1.3 without it. Supplied here (javax.* is loadable from the app class path, unlike java.*).
// The real 1.4 interface declares exactly these two abstract methods (the Java 8 default bodies
// do not exist on 1.3); BC's implementers provide both, so abstract declarations suffice.
public interface Destroyable
{
    void destroy()
        throws DestroyFailedException;

    boolean isDestroyed();
}

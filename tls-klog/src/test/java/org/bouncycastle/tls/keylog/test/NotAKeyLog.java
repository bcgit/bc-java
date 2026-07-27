package org.bouncycastle.tls.keylog.test;

/**
 * A class that is deliberately <em>not</em> a {@link org.bouncycastle.tls.keylog.TlsKeyLog}, used
 * to check that naming one in the key-log security property cannot get arbitrary code run.
 * <p>
 * Both the static initialiser and the constructor record that they ran, in a system property rather
 * than a field of this class &mdash; a field could only be read by loading the class, which is the
 * very thing under test.
 */
public class NotAKeyLog
{
    public static final String CANARY_PROPERTY = "org.bouncycastle.tls.keylog.test.canary";

    static
    {
        System.setProperty(CANARY_PROPERTY, "static initialiser ran");
    }

    public NotAKeyLog()
    {
        System.setProperty(CANARY_PROPERTY, "constructor ran");
    }
}

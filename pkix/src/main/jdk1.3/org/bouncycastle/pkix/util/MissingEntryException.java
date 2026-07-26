package org.bouncycastle.pkix.util;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.Locale;

// NOTE: jdk1.3 overlay. RuntimeException(String, Throwable) is a Java 1.4 constructor absent on
// JDK 1.3, so the base class will not compile here. Mirrors the org.bouncycastle.i18n
// MissingEntryException jdk1.3 overlay: a private cause field with its own getCause() override,
// same as core-into-prov's org.bouncycastle.jce.cert exceptions -- unlike the message-only-drop
// pattern used elsewhere, this class can still carry a real, retrievable cause on 1.3.
public class MissingEntryException
    extends RuntimeException
{

    protected final String resource;
    protected final String key;
    protected final ClassLoader loader;
    protected final Locale locale;

    private Throwable cause;
    private String debugMsg;

    public MissingEntryException(String message, String resource, String key, Locale locale, ClassLoader loader)
    {
        super(message);
        this.resource = resource;
        this.key = key;
        this.locale = locale;
        this.loader = loader;
    }

    public MissingEntryException(String message, Throwable cause, String resource, String key, Locale locale, ClassLoader loader)
    {
        super(message);
        this.cause = cause;
        this.resource = resource;
        this.key = key;
        this.locale = locale;
        this.loader = loader;
    }

    public Throwable getCause()
    {
        return cause;
    }

    public String getKey()
    {
        return key;
    }

    public String getResource()
    {
        return resource;
    }
    
    public ClassLoader getClassLoader()
    {
        return loader;
    }
    
    public Locale getLocale()
    {
        return locale;
    }

    public String getDebugMsg()
    {
        if (debugMsg == null)
        {
            debugMsg = "Can not find entry " + key + " in resource file " + resource + " for the locale " + locale + ".";
            if (loader instanceof URLClassLoader)
            {
                URL[] urls = ((URLClassLoader) loader).getURLs();
                debugMsg += " The following entries in the classpath were searched: ";
                for (int i = 0; i != urls.length; i++)
                {
                    debugMsg += urls[i] + " ";
                }
            }
        }
        return debugMsg;
    }

}

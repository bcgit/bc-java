package org.bouncycastle.jsse.provider;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

/**
 * Privileged file system access used when locating and reading the default key/trust stores.
 * <p>
 * Finding the JRE's default stores is work the provider does on its own behalf rather than on
 * behalf of the caller, so each operation runs inside an
 * {@link AccessController#doPrivileged(PrivilegedAction)} block. Without it, every protection
 * domain on the call stack needs its own {@code java.io.FilePermission} for the JRE's
 * {@code jssecacerts} / {@code cacerts} files before something as ordinary as
 * {@code SSLContext.getDefault()} will work under a security manager.
 */
class FileUtils
{
    static boolean exists(final String path)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Boolean>()
        {
            public Boolean run()
            {
                return Boolean.valueOf(new File(path).exists());
            }
        }).booleanValue();
    }

    static InputStream openBufferedInputStream(final String path)
        throws Exception
    {
        try
        {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<InputStream>()
            {
                public InputStream run()
                    throws Exception
                {
                    return new BufferedInputStream(new FileInputStream(path));
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }

    static void closeInputStream(final InputStream input)
        throws Exception
    {
        try
        {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>()
            {
                public Void run()
                    throws Exception
                {
                    input.close();
                    return null;
                }
            });
        }
        catch (PrivilegedActionException e)
        {
            throw e.getException();
        }
    }
}

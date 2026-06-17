package org.bouncycastle.mail.smime;

import java.io.File;
import java.io.IOException;

/**
 * Pre-Java-7 fallback used by the legacy (jdk1.3/jdk1.4) builds, where {@code java.nio.file} is
 * unavailable. {@link File#createTempFile} honours the umask, so the owner-only permissions the
 * Java 7+ version obtains from {@code Files.createTempFile} cannot be applied here; behaviour
 * matches the historical S/MIME temp-file handling on those JDKs.
 */
class TempFileFactory
{
    static File createTempFile(String prefix, String suffix)
        throws IOException
    {
        return File.createTempFile(prefix, suffix);
    }
}

package org.bouncycastle.mail.smime;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * Creates the backing temp files used for S/MIME streaming content.
 * <p>
 * This (Java 7+) version goes through {@link Files#createTempFile} so the file is created with
 * owner-only permissions (0600 on POSIX, owner-only ACL on Windows). {@link File#createTempFile}
 * honours the umask and so typically leaves the file world-readable, which matters here because
 * the temp files hold decrypted / decompressed / signed plaintext. The legacy {@code jdk1.4} and
 * {@code jdk1.5} source trees override this class with a {@code File.createTempFile} fallback for
 * the pre-Java-7 builds, where {@code java.nio.file} is unavailable.
 */
class TempFileFactory
{
    static File createTempFile(String prefix, String suffix)
        throws IOException
    {
        return Files.createTempFile(prefix, suffix).toFile();
    }
}

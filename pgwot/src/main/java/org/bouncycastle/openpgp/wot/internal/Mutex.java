package org.bouncycastle.openpgp.wot.internal;

import static org.bouncycastle.openpgp.wot.internal.Util.*;

import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

/**
 * Globally used mutex.
 * <p>
 * There is one mutex instance per pgp/gnupg directory. All classes of the WOT use this same mutex. This strategy
 * prevents dead-locks and at the same time allows for maximum concurrency when working with multiple webs-of-trust.
 */
public final class Mutex
{
    private static final WeakHashMap<String, WeakReference<Mutex>> pgpDir2MutexRef = new WeakHashMap<String, WeakReference<Mutex>>();

    private final String pgpDir;

    private Mutex(final String pgpDir)
    {
        this.pgpDir = assertNotNull("pgpDir", pgpDir);
    }

    public static synchronized Mutex forPubringFile(final File pubringFile) {
        assertNotNull("pubringFile", pubringFile);
        return forPgpDir(pubringFile.getParentFile());
    }

    public static synchronized Mutex forPgpDir(final File dir) {
        assertNotNull("dir", dir);
        final String pgpDir;
        try
        {
            pgpDir = dir.getCanonicalPath();
        } catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        final WeakReference<Mutex> ref = pgpDir2MutexRef.get(pgpDir);
        Mutex mutex = ref == null ? null : ref.get();
        if (mutex == null) {
            mutex = new Mutex(pgpDir);
            pgpDir2MutexRef.put(pgpDir, new WeakReference<Mutex>(mutex));
        }
        return mutex;
    }

    @Override
    public String toString()
    {
        return String.format("Mutex['%s']", pgpDir);
    }
}

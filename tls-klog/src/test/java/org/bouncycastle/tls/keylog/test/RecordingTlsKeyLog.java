package org.bouncycastle.tls.keylog.test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.tls.keylog.TlsKeyLog;
import org.bouncycastle.util.Arrays;

/**
 * A {@link TlsKeyLog} that keeps what it is given, so a test can look at it.
 * <p>
 * Loaded by name out of the <code>org.bouncycastle.tls.keylog.class</code> security property, like
 * any other implementation, which means the library constructs the instance and the test never
 * holds a reference to it &mdash; hence the static record.
 */
public class RecordingTlsKeyLog
    implements TlsKeyLog
{
    private static final List entries = Collections.synchronizedList(new ArrayList());

    /**
     * Discard everything recorded so far.
     */
    public static void reset()
    {
        entries.clear();
    }

    /**
     * A snapshot of what has been recorded, in the order it arrived.
     */
    public static List getEntries()
    {
        synchronized (entries)
        {
            return new ArrayList(entries);
        }
    }

    /**
     * Those recorded entries carrying the given RFC 9850 label.
     */
    public static List getEntries(String label)
    {
        List matching = new ArrayList();

        List all = getEntries();
        for (int i = 0; i < all.size(); ++i)
        {
            Entry entry = (Entry)all.get(i);
            if (entry.getLabel().equals(label))
            {
                matching.add(entry);
            }
        }

        return matching;
    }

    public void log(String label, byte[] clientRandom, byte[] secret)
    {
        entries.add(new Entry(label, clientRandom, secret));
    }

    public static class Entry
    {
        private final String label;
        private final byte[] clientRandom;
        private final byte[] secret;

        Entry(String label, byte[] clientRandom, byte[] secret)
        {
            this.label = label;
            this.clientRandom = clientRandom;
            this.secret = secret;
        }

        public String getLabel()
        {
            return label;
        }

        public byte[] getClientRandom()
        {
            return Arrays.clone(clientRandom);
        }

        public byte[] getSecret()
        {
            return Arrays.clone(secret);
        }
    }
}

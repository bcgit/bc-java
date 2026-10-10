package org.bouncycastle.cert.dane;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

/**
 * Class storing DANEEntry objects. An address may have several entries (one per SMIMEA record
 * under its owner name), and all of them are kept.
 */
public class DANEEntryStore
    implements Store
{
    private final List entries;

    DANEEntryStore(List entries)
    {
        this.entries = Collections.unmodifiableList(new ArrayList(entries));
    }

    /**
     * Return a collection of entries matching the passed in selector.
     *
     * @param selector the selector to validate entries against.
     * @return a possibly empty collection of matched entries.
     * @throws StoreException in case of an underlying issue.
     */
    public Collection getMatches(Selector selector)
        throws StoreException
    {
        if (selector == null)
        {
            return entries;
        }

        List results = new ArrayList();

        for (Iterator it = entries.iterator(); it.hasNext();)
        {
            Object next = it.next();
            if (selector.match(next))
            {
                results.add(next);
            }
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Return a Store of X509CertificateHolder objects representing all the certificates associated with
     * entries in the store.
     *
     * @return a Store of X509CertificateHolder.
     */
    public Store toCertificateStore()
    {
        Collection col = this.getMatches(null);
        List certColl = new ArrayList(col.size());

        for (Iterator it = col.iterator(); it.hasNext();)
        {
            DANEEntry entry = (DANEEntry)it.next();

            certColl.add(entry.getCertificate());
        }

        return new CollectionStore(certColl);
    }
}

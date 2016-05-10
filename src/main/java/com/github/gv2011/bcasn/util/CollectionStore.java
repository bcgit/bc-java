package com.github.gv2011.bcasn.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * A simple collection backed store.
 */
public class CollectionStore<T>
    implements Store<T>, Iterable<T>
{
    private Collection<T> _local;

    /**
     * Basic constructor.
     *
     * @param collection - initial contents for the store, this is copied.
     */
    public CollectionStore(
        Collection<T> collection)
    {
        _local = new ArrayList<T>(collection);
    }

    /**
     * Return the matches in the collection for the passed in selector.
     *
     * @param selector the selector to match against.
     * @return a possibly empty collection of matching objects.
     */
    public Collection<T> getMatches(Selector<T> selector)
    {
        if (selector == null)
        {
            return new ArrayList<T>(_local);
        }
        else
        {
            List<T> col = new ArrayList<T>();
            Iterator<T> iter = _local.iterator();

            while (iter.hasNext())
            {
                T obj = iter.next();

                if (selector.match(obj))
                {
                    col.add(obj);
                }
            }

            return col;
        }
    }

    public Iterator<T> iterator()
    {
        return getMatches(null).iterator();
    }
}

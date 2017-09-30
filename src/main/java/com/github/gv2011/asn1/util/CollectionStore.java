package com.github.gv2011.asn1.util;

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
    private final Collection<T> _local;

    /**
     * Basic constructor.
     *
     * @param collection - initial contents for the store, this is copied.
     */
    public CollectionStore(
        final Collection<T> collection)
    {
        _local = new ArrayList<>(collection);
    }

    /**
     * Return the matches in the collection for the passed in selector.
     *
     * @param selector the selector to match against.
     * @return a possibly empty collection of matching objects.
     */
    @Override
    public Collection<T> getMatches(final Selector<T> selector)
    {
        if (selector == null)
        {
            return new ArrayList<>(_local);
        }
        else
        {
            final List<T> col = new ArrayList<>();
            final Iterator<T> iter = _local.iterator();

            while (iter.hasNext())
            {
                final T obj = iter.next();

                if (selector.match(obj))
                {
                    col.add(obj);
                }
            }

            return col;
        }
    }

    @Override
    public Iterator<T> iterator()
    {
        return getMatches(null).iterator();
    }
}

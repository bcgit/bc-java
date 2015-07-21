package org.bouncycastle.util;

import java.util.Collection;

/**
 * A generic interface describing a simple store of objects.
 *
 * @param <T> the object type stored.
 */
public interface Store<T>
{
    /**
     * Return a possibly empty collection of objects that match the criteria implemented
     * in the passed in Selector.
     *
     * @param selector the selector defining the match criteria.
     * @return a collection of matching objects, empty if none available.
     * @throws StoreException if there is a failure during matching.
     */
    Collection<T> getMatches(Selector<T> selector)
        throws StoreException;
}

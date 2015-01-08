package org.bouncycastle.util;

import java.util.Iterator;

/**
 * Utility class to allow use of Iterable feature in JDK 1.5+
 */
public interface Iterable
{
    /**
     * Returns an iterator over a set of elements of type T.
     *
     * @return an Iterator.
     */
    Iterator iterator();
}

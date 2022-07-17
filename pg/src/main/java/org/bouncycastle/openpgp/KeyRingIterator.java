package org.bouncycastle.openpgp;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

class KeyRingIterator<T>
    implements Iterator<T>
{
    private final Iterator<Long> iterator;
    private final Map<Long, T> rings;

    KeyRingIterator(List<Long> ids, Map<Long, T> rings)
    {
        this.iterator = ids.iterator();
        this.rings = rings;
    }

    public boolean hasNext()
    {
        return iterator.hasNext();
    }

    public T next()
    {
        return rings.get(iterator.next());
    }
    
    public void remove()
    {
        throw new UnsupportedOperationException("remove not available");
    }
}

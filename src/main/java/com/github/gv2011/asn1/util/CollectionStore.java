package com.github.gv2011.asn1.util;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


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

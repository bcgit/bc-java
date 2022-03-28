package java.util;

public class Collections
{
    public static final List EMPTY_LIST = unmodifiableList(new ArrayList());
    public static final Set EMPTY_SET = unmodifiableSet(new HashSet());

    private Collections()
    {
    }

    public static Set singleton(Object o)
    {
        Set rv = new HashSet();

        rv.add(o);

        return rv;
    }

    public static Collection unmodifiableCollection(Collection c)
    {
        return new UnmodifiableCollection(c);
    }

    static class UnmodifiableCollection
        implements Collection
    {
        Collection c;

        UnmodifiableCollection(Collection c)
        {
            this.c = c;
        }

        public int size()
        {
            return c.size();
        }

        public boolean isEmpty()
        {
            return c.isEmpty();
        }

        public boolean contains(Object o)
        {
            return c.contains(o);
        }

        public Object[] toArray()
        {
            return c.toArray();
        }

        public Object[] toArray(Object[] a)
        {
            return c.toArray(a);
        }

        public Iterator iterator()
        {
            return new Iterator()
            {
                Iterator i = c.iterator();

                public boolean hasNext()
                {
                    return i.hasNext();
                }

                public Object next()
                {
                    return i.next();
                }

                public void remove()
                {
                    throw new RuntimeException();
                }
            };
        }

        public boolean add(Object o)
        {
            throw new RuntimeException();
        }

        public boolean remove(Object o)
        {
            throw new RuntimeException();
        }

        public boolean containsAll(Collection coll)
        {
            return c.containsAll(coll);
        }

        public boolean addAll(Collection coll)
        {
            throw new RuntimeException();
        }

        public boolean removeAll(Collection coll)
        {
            throw new RuntimeException();
        }

        public boolean retainAll(Collection coll)
        {
            throw new RuntimeException();
        }

        public void clear()
        {
            throw new RuntimeException();
        }

        public String toString()
        {
            return c.toString();
        }
    }

    public static Set unmodifiableSet(Set s)
    {
        return new UnmodifiableSet(s);
    }

    static class UnmodifiableSet
        extends UnmodifiableCollection
        implements Set
    {
        UnmodifiableSet(Set s)
        {
            super(s);
        }

        public boolean equals(Object o)
        {
            return c.equals(o);
        }

        public int hashCode()
        {
            return c.hashCode();
        }
    }

    public static List unmodifiableList(List list)
    {
        return new UnmodifiableList(list);
    }

    static class UnmodifiableList
        extends UnmodifiableCollection
        implements List
    {
        private List list;

        UnmodifiableList(List list)
        {
            super(list);
            this.list = list;
        }

        public boolean equals(Object o)
        {
            return list.equals(o);
        }

        public int hashCode()
        {
            return list.hashCode();
        }

        public Object get(int index)
        {
            return list.get(index);
        }

        public Object set(int index, Object element)
        {
            throw new RuntimeException();
        }

        public void add(int index, Object element)
        {
            throw new RuntimeException();
        }

        public Object remove(int index)
        {
            throw new RuntimeException();
        }

        public int indexOf(Object o)
        {
            return list.indexOf(o);
        }

        public int lastIndexOf(Object o)
        {
            return list.lastIndexOf(o);
        }

        public boolean addAll(int index, Collection c)
        {
            throw new RuntimeException();
        }

        public ListIterator listIterator()
        {
            return listIterator(0);
        }

        public ListIterator listIterator(final int index)
        {
            return new ListIterator()
            {
                ListIterator i = list.listIterator(index);

                public boolean hasNext()
                {
                    return i.hasNext();
                }

                public Object next()
                {
                    return i.next();
                }

                public boolean hasPrevious()
                {
                    return i.hasPrevious();
                }

                public Object previous()
                {
                    return i.previous();
                }

                public int nextIndex()
                {
                    return i.nextIndex();
                }

                public int previousIndex()
                {
                    return i.previousIndex();
                }

                public void remove()
                {
                    throw new RuntimeException();
                }

                public void set(Object o)
                {
                    throw new RuntimeException();
                }

                public void add(Object o)
                {
                    throw new RuntimeException();
                }
            };
        }

        public List subList(int fromIndex, int toIndex)
        {
            return new UnmodifiableList(list.subList(fromIndex, toIndex));
        }
    }

    public static Enumeration enumeration(final Collection c)
    {
        return new Enumeration()
        {
            Iterator i = c.iterator();

            public boolean hasMoreElements()
            {
                return i.hasNext();
            }

            public Object nextElement()
            {
                return i.next();
            }
        };
    }

    public static Map unmodifiableMap(Map s)
    {
        return new UnmodifiableMap(s);
    }

    static class UnmodifiableMap
        implements Map
    {
        private Map c;

        UnmodifiableMap(Map map)
        {
            this.c = map;
        }

        public int size()
        {
            return c.size();
        }

        public boolean isEmpty()
        {
            return c.isEmpty();
        }

        public boolean containsKey(Object o)
        {
            return c.containsKey(o);
        }

        public boolean containsValue(Object o)
        {
            return c.containsValue(o);
        }

        public Object get(Object o)
        {
            return c.get(o);
        }

        public Object put(Object o, Object o2)
        {
            throw new RuntimeException();
        }

        public Object remove(Object o)
        {
            throw new RuntimeException();
        }

        public void putAll(Map map)
        {
            throw new RuntimeException();
        }

        public void clear()
        {
            throw new RuntimeException();
        }

        public Set keySet()
        {
            return Collections.unmodifiableSet(c.keySet());
        }

        public Collection values()
        {
            return new UnmodifiableCollection(c.values());
        }

        public Set entrySet()
        {
            return Collections.unmodifiableSet(c.entrySet());
        }

        public boolean equals(Object o)
        {
            return c.equals(o);
        }

        public int hashCode()
        {
            return c.hashCode();
        }

        public String toString()
        {
            return c.toString();
        }
    }

    public static Set synchronizedSet(Set set)
    {
        return new SyncSet(set);
    }

    static class SyncSet implements Set
    {
        private Set base;

        SyncSet(Set base)
        {
            this.base = base;
        }

        public int size()
        {
            synchronized (base)
            {
                return base.size();
            }
        }

        public boolean isEmpty()
        {
            synchronized (base)
            {
                return base.isEmpty();
            }
        }

        public boolean contains(Object o)
        {
            synchronized (base)
            {
                return base.contains(o);
            }
        }

        public Iterator iterator()
        {
            synchronized (base)
            {
                return new ArrayList(base).iterator();
            }
        }

        public Object[] toArray()
        {
            synchronized (base)
            {
                return base.toArray();
            }
        }

        public boolean add(Object o)
        {
            synchronized (base)
            {
                return base.add(o);
            }
        }

        public boolean remove(Object o)
        {
            synchronized (base)
            {
                return base.remove(o);
            }
        }

        public boolean addAll(Collection collection)
        {
            synchronized (base)
            {
                return base.addAll(collection);
            }
        }

        public void clear()
        {
            synchronized (base)
            {
                base.clear();
            }
        }

        public boolean removeAll(Collection collection)
        {
            synchronized (base)
            {
                return base.removeAll(collection);
            }
        }

        public boolean retainAll(Collection collection)
        {
            synchronized (base)
            {
                return base.retainAll(collection);
            }
        }

        public boolean containsAll(Collection collection)
        {
            synchronized (base)
            {
                return base.containsAll(collection);
            }
        }

        public Object[] toArray(Object[] objects)
        {
            synchronized (base)
            {
                return base.toArray(objects);
            }
        }
    }
}

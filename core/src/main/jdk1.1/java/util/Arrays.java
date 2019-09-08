package java.util;

public class Arrays
{

    private Arrays() {}
    
    public static void fill(int[] ret, int v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = v;
       }
    }

    public static void fill(byte[] ret, int v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = (byte)v;
       }
    }

    public static void fill(boolean[] ret, boolean v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = v;
       }
    }

    public static void fill(char[] ret, char v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = v;
       }
    }

    public static void fill(long[] ret, long v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = v;
       }
    }

    public static void fill(short[] ret, short v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = v;
       }
    }

    public static void fill(Object[] ret, Object v)
    {
       for (int i = 0; i != ret.length; i++)
       {
           ret[i] = v;
       }
    }

    public static void fill(boolean[] a, int fromIndex, int toIndex, boolean val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static void fill(byte[] a, int fromIndex, int toIndex, byte val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static void fill(char[] a, int fromIndex, int toIndex, char val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static void fill(int[] a, int fromIndex, int toIndex, int val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static void fill(short[] a, int fromIndex, int toIndex, short val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static void fill(long[] a, int fromIndex, int toIndex, long val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static void fill(Object[] a, int fromIndex, int toIndex, Object val)
    {
       for (int i = fromIndex; i != toIndex; i++)
       {
           a[i] = val;
       }
    }

    public static boolean equals(boolean[] a, boolean[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }

    public static boolean equals(byte[] a, byte[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }

    public static boolean equals(char[] a, char[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }

    public static boolean equals(short[] a, short[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }

    public static boolean equals(int[] a, int[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }

    public static boolean equals(long[] a, long[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (a[i] != a2[i])
                return false;

        return true;
    }

    public static boolean equals(Object[] a, Object[] a2) {
        if (a==a2)
            return true;
        if (a==null || a2==null)
            return false;

        int length = a.length;
        if (a2.length != length)
            return false;

        for (int i=0; i<length; i++)
            if (!a[i].equals(a2[i]))
                return false;

        return true;
    }

    public static List asList(Object[] a) {
    return new ArrayList(a);
    }

    private static class ArrayList extends AbstractList implements java.io.Serializable
    {
    private Object[] a;

    ArrayList(Object[] array)
    {
        a = array;
    }

    public int size()
    {
        return a.length;
    }

    public Object[] toArray()
    {
        return (Object[]) a.clone();
    }

    public Object get(int index)
    {
        return a[index];
    }

    public Object set(int index, Object element)
    {
        Object oldValue = a[index];
        a[index] = element;
        return oldValue;
    }

        public int indexOf(Object o)
    {
            if (o==null)
        {
                for (int i=0; i<a.length; i++)
                    if (a[i]==null)
                        return i;
            }
        else
        {
                for (int i=0; i<a.length; i++)
                    if (o.equals(a[i]))
                        return i;
            }
            return -1;
        }

        public boolean contains(Object o)
    {
            return indexOf(o) != -1;
        }
    }

}

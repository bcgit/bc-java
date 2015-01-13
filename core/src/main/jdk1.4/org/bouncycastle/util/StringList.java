package org.bouncycastle.util;

public interface StringList
    extends Iterable
{
    boolean add(String s);

    String get(int index);

    int size();

    String[] toStringArray();

    /**
     * Return a section of the contents of the list. If the list is too short the array is filled with nulls.
     *
     * @param from the initial index of the range to be copied, inclusive
     * @param to the final index of the range to be copied, exclusive.
     * @return an array of length to - from
     */
    String[] toStringArray(int from, int to);
}

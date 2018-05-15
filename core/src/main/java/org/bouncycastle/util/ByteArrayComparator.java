package org.bouncycastle.util;

import java.util.Comparator;

/**
 * Comparator for byte arrays
 */
public class ByteArrayComparator implements Comparator <byte[]> {

  public int compare (final byte[] left, final byte[] right) {

    for (int i = 0, j = 0; i < left.length && j < right.length; i++, j++)
    {
      int a = (left[i] & 0xff);
      int b = (right[j] & 0xff);

      if (a != b)
      {
        return a - b;
      }
    }
    return left.length - right.length;
  }

}

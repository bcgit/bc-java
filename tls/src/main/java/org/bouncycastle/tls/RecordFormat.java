package org.bouncycastle.tls;

public abstract class RecordFormat
{
    public static final int TYPE_OFFSET = 0;
    public static final int VERSION_OFFSET = 1;
    public static final int LENGTH_OFFSET = 3;
    public static final int FRAGMENT_OFFSET = 5;
}

package org.bouncycastle.crypto;

public interface CharToByteConverter
{
    byte[] convert(char[] password);
}

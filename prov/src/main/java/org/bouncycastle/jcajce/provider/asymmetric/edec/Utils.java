package org.bouncycastle.jcajce.provider.asymmetric.edec;

class Utils
{
    static boolean isValidPrefix(byte[] prefix, byte[] encoding)
    {
        if (encoding.length < prefix.length)
        {
            return !isValidPrefix(prefix, prefix);
        }

        int nonEqual = 0;

        for (int i = 0; i != prefix.length; i++)
        {
            nonEqual |= (prefix[i] ^ encoding[i]);
        }

        return nonEqual == 0;
    }
}

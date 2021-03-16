package org.bouncycastle.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AlphabetMapper;

/**
 * A basic alphabet mapper that just creates a mapper based on the
 * passed in array of characters.
 */
public class BasicAlphabetMapper
    implements AlphabetMapper
{
    private Map<Character, Integer> indexMap = new HashMap<Character, Integer>();
    private Map<Integer, Character> charMap = new HashMap<Integer, Character>();

    /**
     * Base constructor.
     *
     * @param alphabet a String of characters making up the alphabet.
     */
    public BasicAlphabetMapper(String alphabet)
    {
        this(alphabet.toCharArray());
    }

    /**
     * Base constructor.
     *
     * @param alphabet an array of characters making up the alphabet.
     */
    public BasicAlphabetMapper(char[] alphabet)
    {
        for (int i = 0; i != alphabet.length; i++)
        {
            if (indexMap.containsKey(alphabet[i]))
            {
                throw new IllegalArgumentException("duplicate key detected in alphabet: " + alphabet[i]);
            }
            indexMap.put(alphabet[i], i);
            charMap.put(i, alphabet[i]);
        }
    }

    public int getRadix()
    {
        return indexMap.size();
    }

    public byte[] convertToIndexes(char[] input)
    {
        byte[] out;

        if (indexMap.size() <= 256)
        {
            out = new byte[input.length];
            for (int i = 0; i != input.length; i++)
            {
                out[i] = indexMap.get(input[i]).byteValue();
            }
        }
        else
        {
            out = new byte[input.length * 2];
            for (int i = 0; i != input.length; i++)
            {
                int idx = indexMap.get(input[i]);
                out[i * 2] = (byte)((idx >> 8) & 0xff);
                out[i * 2  + 1] = (byte)(idx & 0xff);
            }
        }

        return out;
    }

    public char[] convertToChars(byte[] input)
    {
        char[] out;

        if (charMap.size() <= 256)
        {
            out = new char[input.length];
            for (int i = 0; i != input.length; i++)
            {
                out[i] = charMap.get(input[i] & 0xff);
            }
        }
        else
        {
            if ((input.length & 0x1) != 0)
            {
                throw new IllegalArgumentException("two byte radix and input string odd length");
            }
            
            out = new char[input.length / 2];
            for (int i = 0; i != input.length; i += 2)
            {
                out[i / 2] = charMap.get(((input[i] << 8) & 0xff00) | (input[i + 1] & 0xff));
            }
        }

        return out;
    }
}

package org.bouncycastle.util.encoders;

/**
 * Utilities for working with UTF-8 encodings.
 * 
 * Decoding of UTF-8 is based on a presentation by Bob Steagall at CppCon2018 (see
 * https://github.com/BobSteagall/CppCon2018). It uses a Deterministic Finite Automaton (DFA) to
 * recognize and decode multi-byte code points.
 */
public class UTF8
{
    // Constants for the categorization of code units
    private static final byte C_ILL = 0;            //- C0..C1, F5..FF  ILLEGAL octets that should never appear in a UTF-8 sequence
    private static final byte C_CR1 = 1;            //- 80..8F          Continuation range 1
    private static final byte C_CR2 = 2;            //- 90..9F          Continuation range 2
    private static final byte C_CR3 = 3;            //- A0..BF          Continuation range 3
    private static final byte C_L2A = 4;            //- C2..DF          Leading byte range A / 2-byte sequence
    private static final byte C_L3A = 5;            //- E0              Leading byte range A / 3-byte sequence
    private static final byte C_L3B = 6;            //- E1..EC, EE..EF  Leading byte range B / 3-byte sequence
    private static final byte C_L3C = 7;            //- ED              Leading byte range C / 3-byte sequence
    private static final byte C_L4A = 8;            //- F0              Leading byte range A / 4-byte sequence
    private static final byte C_L4B = 9;            //- F1..F3          Leading byte range B / 4-byte sequence
    private static final byte C_L4C = 10;           //- F4              Leading byte range C / 4-byte sequence
//  private static final byte C_ASC = 11;           //- 00..7F          ASCII leading byte range

    // Constants for the states of a DFA
    private static final byte S_ERR = -2;           //- Error state
    private static final byte S_END = -1;           //- End (or Accept) state
    private static final byte S_CS1 = 0x00;         //- Continuation state 1
    private static final byte S_CS2 = 0x10;         //- Continuation state 2
    private static final byte S_CS3 = 0x20;         //- Continuation state 3
    private static final byte S_P3A = 0x30;         //- Partial 3-byte sequence state A
    private static final byte S_P3B = 0x40;         //- Partial 3-byte sequence state B
    private static final byte S_P4A = 0x50;         //- Partial 4-byte sequence state A
    private static final byte S_P4B = 0x60;         //- Partial 4-byte sequence state B

    private static final short[] firstUnitTable = new short[128];
    private static final byte[] transitionTable = new byte[S_P4B + 16];

    private static void fill(byte[] table, int first, int last, byte b)
    {
        for (int i = first; i <= last; ++i)
        {
            table[i] = b;
        }
    }

    static
    {
        byte[] categories = new byte[128];
        fill(categories, 0x00, 0x0F, C_CR1);
        fill(categories, 0x10, 0x1F, C_CR2);
        fill(categories, 0x20, 0x3F, C_CR3);
        fill(categories, 0x40, 0x41, C_ILL);
        fill(categories, 0x42, 0x5F, C_L2A);
        fill(categories, 0x60, 0x60, C_L3A);
        fill(categories, 0x61, 0x6C, C_L3B);
        fill(categories, 0x6D, 0x6D, C_L3C);
        fill(categories, 0x6E, 0x6F, C_L3B);
        fill(categories, 0x70, 0x70, C_L4A);
        fill(categories, 0x71, 0x73, C_L4B);
        fill(categories, 0x74, 0x74, C_L4C);
        fill(categories, 0x75, 0x7F, C_ILL);

        fill(transitionTable, 0, transitionTable.length - 1, S_ERR);
        fill(transitionTable, S_CS1 + 0x8, S_CS1 + 0xB, S_END);
        fill(transitionTable, S_CS2 + 0x8, S_CS2 + 0xB, S_CS1);
        fill(transitionTable, S_CS3 + 0x8, S_CS3 + 0xB, S_CS2);
        fill(transitionTable, S_P3A + 0xA, S_P3A + 0xB, S_CS1);
        fill(transitionTable, S_P3B + 0x8, S_P3B + 0x9, S_CS1);
        fill(transitionTable, S_P4A + 0x9, S_P4A + 0xB, S_CS2);
        fill(transitionTable, S_P4B + 0x8, S_P4B + 0x8, S_CS2);

        byte[] firstUnitMasks = { 0x00, 0x00, 0x00, 0x00, 0x1F, 0x0F, 0x0F, 0x0F, 0x07, 0x07, 0x07 };
        byte[] firstUnitTransitions = { S_ERR, S_ERR, S_ERR, S_ERR, S_CS1, S_P3A, S_CS2, S_P3B, S_P4A, S_CS3, S_P4B };

        for (int i = 0x00; i < 0x80; ++i)
        {
            byte category = categories[i];

            int codePoint = i & firstUnitMasks[category];
            byte state = firstUnitTransitions[category];

            firstUnitTable[i] = (short)((codePoint << 8) | state);
        }
    }

    /**
     * Transcode a UTF-8 encoding into a UTF-16 representation. In the general case the output
     * {@code utf16} array should be at least as long as the input {@code utf8} one to handle
     * arbitrary inputs. The number of output UTF-16 code units is returned, or -1 if any errors are
     * encountered (in which case an arbitrary amount of data may have been written into the output
     * array). Errors that will be detected are malformed UTF-8, including incomplete, truncated or
     * "overlong" encodings, and unmappable code points. In particular, no unmatched surrogates will
     * be produced. An error will also result if {@code utf16} is found to be too small to store the
     * complete output.
     * 
     * @param utf8
     *            A non-null array containing a well-formed UTF-8 encoding.
     * @param utf16
     *            A non-null array, at least as long as the {@code utf8} array in order to ensure
     *            the output will fit.
     * @return The number of UTF-16 code units written to {@code utf16} (beginning from index 0), or
     *         else -1 if the input was either malformed or encoded any unmappable characters, or if
     *         the {@code utf16} is too small.
     */
    public static int transcodeToUTF16(byte[] utf8, char[] utf16)
    {
        int i = 0, j = 0;

        while (i < utf8.length)
        {
            byte codeUnit = utf8[i++];
            if (codeUnit >= 0)
            {
                if (j >= utf16.length) { return -1; }

                utf16[j++] = (char)codeUnit;
                continue;
            }

            short first = firstUnitTable[codeUnit & 0x7F];
            int codePoint = first >>> 8;
            byte state = (byte)first;

            while (state >= 0)
            {
                if (i >= utf8.length) { return -1; }

                codeUnit = utf8[i++];
                codePoint = (codePoint << 6) | (codeUnit & 0x3F);
                state = transitionTable[state + ((codeUnit & 0xFF) >>> 4)];
            }

            if (state == S_ERR) { return -1; }

            if (codePoint <= 0xFFFF)
            {
                if (j >= utf16.length) { return -1; }

                // Code points from U+D800 to U+DFFF are caught by the DFA
                utf16[j++] = (char)codePoint;
            }
            else
            {
                if (j >= utf16.length - 1) { return -1; }

                // Code points above U+10FFFF are caught by the DFA
                utf16[j++] = (char)(0xD7C0 + (codePoint >>> 10));
                utf16[j++] = (char)(0xDC00 | (codePoint & 0x3FF));
            }
        }

        return j;
    }
}

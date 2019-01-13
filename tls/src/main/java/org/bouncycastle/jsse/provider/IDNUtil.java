package org.bouncycastle.jsse.provider;

import java.lang.reflect.Method;

public class IDNUtil
{
    public static final int ALLOW_UNASSIGNED;
    public static final int USE_STD3_ASCII_RULES;

    public static final Method toASCIIMethod;
    public static final Method toUnicodeMethod;

    private static final String IDN_CLASSNAME = "java.net.IDN";
//    private static final String ACE_PREFIX = "xn--";
    private static final int MAX_LABEL_LENGTH = 63;

    static
    {
        ALLOW_UNASSIGNED = ReflectionUtil.getStaticIntOrDefault(IDN_CLASSNAME, "ALLOW_UNASSIGNED", 0x01);
        USE_STD3_ASCII_RULES = ReflectionUtil.getStaticIntOrDefault(IDN_CLASSNAME, "USE_STD3_ASCII_RULES", 0x02);
        toASCIIMethod = ReflectionUtil.getMethod(IDN_CLASSNAME, "toASCII", String.class, int.class);
        toUnicodeMethod = ReflectionUtil.getMethod(IDN_CLASSNAME, "toUnicode", String.class, int.class);
    }

    public static String toASCII(String input, int flag)
    {
        if (null != toASCIIMethod)
        {
            return (String)ReflectionUtil.invokeMethod(null, toASCIIMethod, input, flag);
        }

        if (isRoot(input))
        {
            return ".";
        }

        StringBuilder result = new StringBuilder();

        int len = input.length(), pos = 0, sepPos;
        while (pos < len)
        {
            sepPos = findSeparator(input, pos);

            String label = input.substring(pos, sepPos);
            String asciiLabel = toAsciiLabel(label, flag);
            result.append(asciiLabel);
            if (sepPos < input.length())
            {
               result.append('.');
            }
            pos = sepPos + 1;
        }

        return result.toString();
    }

    public static String toUnicode(String input, int flag)
    {
        // NOTE: toUnicode should never fail; it is best effort

        if (null != toUnicodeMethod)
        {
            return (String)ReflectionUtil.invokeMethod(null, toUnicodeMethod, input, flag);
        }

        if (isRoot(input))
        {
            return ".";
        }

        StringBuilder result = new StringBuilder();

        int len = input.length(), pos = 0, sepPos;
        while (pos < len)
        {
            sepPos = findSeparator(input, pos);

            String label = input.substring(pos, sepPos);
            String unicodeLabel = toUnicodeLabel(label, flag);
            result.append(unicodeLabel);
            if (sepPos < input.length())
            {
               result.append('.');
            }
            pos = sepPos + 1;
        }

        return result.toString();
    }

    private static int findSeparator(String s, int pos)
    {
        while (pos < s.length())
        {
            if (isSeparator(s.charAt(pos)))
            {
                break;
            }
            ++pos;
        }
        return pos;
    }

    private static boolean isAllAscii(CharSequence s)
    {
        for (int i = 0; i < s.length(); ++i)
        {
            int c = s.charAt(i);
            if (c >= 0x80)
            {
                return false;
            }
        }
        return true;
    }

    private static boolean hasAnyNonLDHAscii(CharSequence s)
    {
        for (int i = 0; i < s.length(); ++i)
        {
            int ch = s.charAt(i);
            if ((0x0000 <= ch && ch <= 0x002C) ||
                (0x002E <= ch && ch <= 0x002F) ||
                (0x003A <= ch && ch <= 0x0040) ||
                (0x005B <= ch && ch <= 0x0060) ||
                (0x007B <= ch && ch <= 0x007F))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean isRoot(String s)
    {
        return s.length() == 1 && isSeparator(s.charAt(0));
    }

    private static boolean isSeparator(char c)
    {
        switch (c)
        {
        case '.':
        case '\u3002':
        case '\uFF0E':
        case '\uFF61':
            return true;
        default:
            return false;
        }
    }

//    private static boolean startsWithACEPrefix(CharSequence s)
//    {
//        int len = ACE_PREFIX.length();
//        if (s.length() < len)
//        {
//            return false;
//        }
//        for (int i = 0; i < len; ++i)
//        {
//            char c = s.charAt(i);
//            if (ACE_PREFIX.charAt(i) != toAsciiLower(c))
//            {
//                return false;
//            }
//        }
//        return true;
//    }

    private static String toAsciiLabel(String s, int flag)
    {
        if (s.length() < 1)
        {
            throw new IllegalArgumentException("Domain name label cannot be empty");
        }

        boolean allAscii = isAllAscii(s);
        if (!allAscii)
        {
            // TODO[jsse] Implement Nameprep and Punycode?
            throw new UnsupportedOperationException("IDN support incomplete");
        }

        boolean useSTD3ASCIIRules = ((flag & USE_STD3_ASCII_RULES) != 0);
        if (useSTD3ASCIIRules)
        {
            if (hasAnyNonLDHAscii(s))
            {
                throw new IllegalArgumentException("Domain name label cannot contain non-LDH characters");
            }

            if ('-' == s.charAt(0) || '-' == s.charAt(s.length() - 1))
            {
                throw new IllegalArgumentException("Domain name label cannot begin or end with a hyphen");
            }
        }

        if (MAX_LABEL_LENGTH < s.length())
        {
            throw new IllegalArgumentException("Domain name label length cannot be more than " + MAX_LABEL_LENGTH);
        }

        return s;
    }

//    private static char toAsciiLower(char c)
//    {
//        if (c < 'A' || 'Z' < c)
//        {
//            return c;
//        }
//
//        return (char)(c - 'A' + 'a');
//    }

//    private static void toAsciiLower(CharSequence s, StringBuilder output)
//    {
//        int len = s.length();
//        for (int i = 0; i < len; ++i)
//        {
//            char c = s.charAt(i);
//            output.append(toAsciiLower(c));
//        }
//    }

    private static String toUnicodeLabel(String s, int flag)
    {
        // TODO[jsse] Implement Nameprep and Punycode?
        return s;
    }
}

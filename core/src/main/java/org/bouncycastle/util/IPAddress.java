package org.bouncycastle.util;

/**
 * Utility methods for processing String objects containing IP addresses.
 */
public class IPAddress
{
    /**
     * Validate the given IPv4 or IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address, false otherwise
     */
    public static boolean isValid(String address)
    {
        return isValidIPv4(address) || isValidIPv6(address);
    }

    /**
     * Validate the given IPv4 or IPv6 address and netmask.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid address with netmask, false otherwise
     */
    public static boolean isValidWithNetMask(String address)
    {
        return isValidIPv4WithNetmask(address) || isValidIPv6WithNetmask(address);
    }

    /**
     * Validate the given IPv4 address.
     * 
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv4 address, false otherwise
     */
    public static boolean isValidIPv4(String address)
    {
        int length = address.length();
        if (length < 7 || length > 15)
        {
            return false;
        }

        int pos = 0;
        for (int octetIndex = 0; octetIndex < 3; ++octetIndex)
        {
            int end = address.indexOf('.', pos);

            if (!isParseableIPv4Octet(address, pos, end))
            {
                return false;
            }

            pos = end + 1;
        }

        return isParseableIPv4Octet(address, pos, length);
    }

    public static boolean isValidIPv4WithNetmask(String address)
    {
        int index = address.indexOf("/");
        if (index < 1)
        {
            return false;
        }

        String before = address.substring(0, index);
        String after = address.substring(index + 1);

        return isValidIPv4(before) && (isValidIPv4(after) || isParseableIPv4Mask(after));
    }

    /**
     * Validate the given IPv6 address.
     *
     * @param address the IP address as a String.
     *
     * @return true if a valid IPv6 address, false otherwise
     */
    public static boolean isValidIPv6(String address)
    {
        if (address.length() == 0)
        {
            return false;
        }

        char firstChar = address.charAt(0);
        if (firstChar != ':' && Character.digit(firstChar, 16) < 0)
        {
            return false;
        }        

        int segmentCount = 0;
        String temp = address + ":";
        boolean doubleColonFound = false;

        int pos = 0, end;
        while (pos < temp.length() && (end = temp.indexOf(':', pos)) >= pos)
        {
            if (segmentCount == 8)
            {
                return false;
            }

            if (pos != end)
            {
                String value = temp.substring(pos, end);

                if (end == temp.length() - 1 && value.indexOf('.') > 0)
                {
                    // add an extra one as address covers 2 words.
                    if (++segmentCount == 8)
                    {
                        return false;
                    }
                    if (!isValidIPv4(value))
                    {
                        return false;
                    }
                }
                else if (!isParseableIPv6Segment(temp, pos, end))
                {
                    return false;
                }
            }
            else
            {
                if (end != 1 && end != temp.length() - 1 && doubleColonFound)
                {
                    return false;
                }
                doubleColonFound = true;
            }

            pos = end + 1;
            ++segmentCount;
        }

        return segmentCount == 8 || doubleColonFound;
    }

    public static boolean isValidIPv6WithNetmask(String address)
    {
        int index = address.indexOf("/");
        if (index < 1)
        {
            return false;
        }

        String before = address.substring(0, index);
        String after = address.substring(index + 1);

        return isValidIPv6(before) && (isValidIPv6(after) || isParseableIPv6Mask(after));
    }

    private static boolean isParseableIPv4Mask(String s)
    {
        return isParseable(s, 0, s.length(), 10, 2, false, 0, 32);
    }

    private static boolean isParseableIPv4Octet(String s, int pos, int end)
    {
        return isParseable(s, pos, end, 10, 3, true, 0, 255);
    }

    private static boolean isParseableIPv6Mask(String s)
    {
        return isParseable(s, 0, s.length(), 10, 3, false, 1, 128);
    }

    private static boolean isParseableIPv6Segment(String s, int pos, int end)
    {
        return isParseable(s, pos, end, 16, 4, true, 0x0000, 0xFFFF);
    }

    private static boolean isParseable(String s, int pos, int end, int radix, int maxLength, boolean allowLeadingZero,
        int minValue, int maxValue)
    {
        int length = end - pos;
        if (length < 1 | length > maxLength)
        {
            return false;
        }

        boolean checkLeadingZero = length > 1 & !allowLeadingZero; 
        if (checkLeadingZero && Character.digit(s.charAt(pos), radix) <= 0)
        {
            return false;
        }

        int value = 0;
        while (pos < end)
        {
            char c = s.charAt(pos++);
            int d = Character.digit(c, radix);
            if (d < 0)
            {
                return false;
            }

            value *= radix;
            value += d;
        }

        return value >= minValue & value <= maxValue;
    }
}

package org.bouncycastle.openpgp.smartcard.test;

public class SmartCardTestProperties
{
    public static final char[] DEFAULT_ADMIN_PIN = "12345678".toCharArray();
    public static final char[] DEFAULT_USER_PIN = "123456".toCharArray();

    private final Integer serialNumber;
    private final char[] adminPin;
    private final char[] userPin;

    public SmartCardTestProperties(Integer serialNumber)
    {
        this(serialNumber, DEFAULT_ADMIN_PIN, DEFAULT_USER_PIN);
    }

    public SmartCardTestProperties(Integer serialNumber,
                                   char[] adminPin,
                                   char[] userPin)
    {
        this.serialNumber = serialNumber;
        this.adminPin = adminPin;
        this.userPin = userPin;
    }

    public Integer getSerialNumber()
    {
        return serialNumber;
    }

    public char[] getAdminPin()
    {
        return adminPin;
    }

    public char[] getUserPin()
    {
        return userPin;
    }
}

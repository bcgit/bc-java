package com.github.gv2011.bcasn.asn1.test;

import java.io.IOException;

import com.github.gv2011.bcasn.ASN1Primitive;
import com.github.gv2011.bcasn.ASN1String;
import com.github.gv2011.bcasn.DERBMPString;
import com.github.gv2011.bcasn.DERBitString;
import com.github.gv2011.bcasn.DERGeneralString;
import com.github.gv2011.bcasn.DERIA5String;
import com.github.gv2011.bcasn.DERNumericString;
import com.github.gv2011.bcasn.DERPrintableString;
import com.github.gv2011.bcasn.DERT61String;
import com.github.gv2011.bcasn.DERUTF8String;
import com.github.gv2011.bcasn.DERUniversalString;
import com.github.gv2011.bcasn.DERVisibleString;
import com.github.gv2011.bcasn.util.Strings;
import com.github.gv2011.bcasn.util.test.SimpleTest;

/**
 * X.690 test example
 */
public class StringTest
    extends SimpleTest
{
    public String getName()
    {
        return "String";
    }

    public void performTest()
        throws IOException
    {
        DERBitString bs = new DERBitString(
            new byte[] { (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xab,(byte)0xcd,(byte)0xef });

        if (!bs.getString().equals("#0309000123456789ABCDEF"))
        {
            fail("DERBitString.getString() result incorrect");
        }

        if (!bs.toString().equals("#0309000123456789ABCDEF"))
        {
            fail("DERBitString.toString() result incorrect");
        }

        bs = new DERBitString(
            new byte[] { (byte)0xfe,(byte)0xdc,(byte)0xba,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10 });

        if (!bs.getString().equals("#030900FEDCBA9876543210"))
        {
            fail("DERBitString.getString() result incorrect");
        }

        if (!bs.toString().equals("#030900FEDCBA9876543210"))
        {
            fail("DERBitString.toString() result incorrect");
        }

        DERUniversalString us = new DERUniversalString(
            new byte[] { (byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xab,(byte)0xcd,(byte)0xef });

        if (!us.getString().equals("#1C080123456789ABCDEF"))
        {
            fail("DERUniversalString.getString() result incorrect");
        }

        if (!us.toString().equals("#1C080123456789ABCDEF"))
        {
            fail("DERUniversalString.toString() result incorrect");
        }

        us = new DERUniversalString(
            new byte[] { (byte)0xfe,(byte)0xdc,(byte)0xba,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10 });

        if (!us.getString().equals("#1C08FEDCBA9876543210"))
        {
            fail("DERUniversalString.getString() result incorrect");
        }

        if (!us.toString().equals("#1C08FEDCBA9876543210"))
        {
            fail("DERUniversalString.toString() result incorrect");
        }

        byte[] t61Bytes = new byte[] { -1, -2, -3, -4, -5, -6, -7, -8 };
        String t61String = new String(t61Bytes, "iso-8859-1");
        DERT61String t61 = new DERT61String(Strings.fromByteArray(t61Bytes));

        if (!t61.getString().equals(t61String))
        {
            fail("DERT61String.getString() result incorrect");
        }

        if (!t61.toString().equals(t61String))
        {
            fail("DERT61String.toString() result incorrect");
        }

        char[] shortChars = new char[] { 'a', 'b', 'c', 'd', 'e'};
        char[] longChars = new char[1000];

        for (int i = 0; i != longChars.length; i++)
        {
            longChars[i] = 'X';
        }

        checkString(new DERBMPString(new String(shortChars)), new DERBMPString(new String(longChars)));
        checkString(new DERUTF8String(new String(shortChars)), new DERUTF8String(new String(longChars)));
        checkString(new DERIA5String(new String(shortChars)), new DERIA5String(new String(longChars)));
        checkString(new DERPrintableString(new String(shortChars)), new DERPrintableString(new String(longChars)));
        checkString(new DERVisibleString(new String(shortChars)), new DERVisibleString(new String(longChars)));
        checkString(new DERGeneralString(new String(shortChars)), new DERGeneralString(new String(longChars)));
        checkString(new DERT61String(new String(shortChars)), new DERT61String(new String(longChars)));

        shortChars = new char[] { '1', '2', '3', '4', '5'};
        longChars = new char[1000];

        for (int i = 0; i != longChars.length; i++)
        {
            longChars[i] = '1';
        }

        checkString(new DERNumericString(new String(shortChars)), new DERNumericString(new String(longChars)));

        byte[] shortBytes = new byte[] { (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e'};
        byte[] longBytes = new byte[1000];

        for (int i = 0; i != longChars.length; i++)
        {
            longBytes[i] = (byte)'X';
        }

        checkString(new DERUniversalString(shortBytes), new DERUniversalString(longBytes));

    }

    private void checkString(ASN1String shortString, ASN1String longString)
        throws IOException
    {
        ASN1String short2 = (ASN1String)ASN1Primitive.fromByteArray(((ASN1Primitive)shortString).getEncoded());

        if (!shortString.toString().equals(short2.toString()))
        {
            fail(short2.getClass().getName() + " shortBytes result incorrect");
        }

        ASN1String long2 = (ASN1String)ASN1Primitive.fromByteArray(((ASN1Primitive)longString).getEncoded());

        if (!longString.toString().equals(long2.toString()))
        {
            fail(long2.getClass().getName() + " longBytes result incorrect");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new StringTest());
    }
}

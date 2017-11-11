package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


import static com.github.gv2011.util.bytes.ByteUtils.parseHex;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.util.bytes.ByteUtils;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

/**
 * X.690 test example
 */
public class StringTest {

  @Test
  public void test() throws IOException {
    DERBitString bs = new DERBitString(parseHex("01 23 45 67 89 ab cd ef"));

    if (!bs.getString().equals("#0309000123456789ABCDEF")) {
      fail("DERBitString.getString() result incorrect");
    }

    if (!bs.toString().equals("#0309000123456789ABCDEF")) {
      fail("DERBitString.toString() result incorrect");
    }

    bs = new DERBitString(parseHex("fe dc ba 98 76 54 32 10"));

    if (!bs.getString().equals("#030900FEDCBA9876543210")) {
      fail("DERBitString.getString() result incorrect");
    }

    if (!bs.toString().equals("#030900FEDCBA9876543210")) {
      fail("DERBitString.toString() result incorrect");
    }

    DERUniversalString us = new DERUniversalString(parseHex("01 23 45 67 89 ab cd ef"));

    if (!us.getString().equals("#1C080123456789ABCDEF")) {
      fail("DERUniversalString.getString() result incorrect");
    }

    if (!us.toString().equals("#1C080123456789ABCDEF")) {
      fail("DERUniversalString.toString() result incorrect");
    }

    us = new DERUniversalString(parseHex("fe dc ba 98 76 54 32 10"));

    if (!us.getString().equals("#1C08FEDCBA9876543210")) {
      fail("DERUniversalString.getString() result incorrect");
    }

    if (!us.toString().equals("#1C08FEDCBA9876543210")) {
      fail("DERUniversalString.toString() result incorrect");
    }

    final Bytes t61Bytes = ByteUtils.newBytes(
      (byte)-1, (byte)-2, (byte)-3, (byte)-4, (byte)-5, (byte)-6, (byte)-7, (byte)-8
    );
    final String t61String = new String(t61Bytes.toByteArray(), StandardCharsets.ISO_8859_1);
    final DERT61String t61 = new DERT61String(Strings.fromByteArray(t61Bytes));

    if (!t61.getString().equals(t61String)) {
      fail("DERT61String.getString() result incorrect");
    }

    if (!t61.toString().equals(t61String)) {
      fail("DERT61String.toString() result incorrect");
    }

    char[] shortChars = new char[] { 'a', 'b', 'c', 'd', 'e' };
    char[] longChars = new char[1000];

    for (int i = 0; i != longChars.length; i++) {
      longChars[i] = 'X';
    }

    checkString(new DERBMPString(new String(shortChars)), new DERBMPString(new String(longChars)));
    checkString(new DERUTF8String(new String(shortChars)), new DERUTF8String(new String(longChars)));
    checkString(new DERIA5String(new String(shortChars)), new DERIA5String(new String(longChars)));
    checkString(new DERPrintableString(new String(shortChars)), new DERPrintableString(new String(longChars)));
    checkString(new DERVisibleString(new String(shortChars)), new DERVisibleString(new String(longChars)));
    checkString(new DERGeneralString(new String(shortChars)), new DERGeneralString(new String(longChars)));
    checkString(new DERT61String(new String(shortChars)), new DERT61String(new String(longChars)));

    shortChars = new char[] { '1', '2', '3', '4', '5' };
    longChars = new char[1000];

    for (int i = 0; i != longChars.length; i++) {
      longChars[i] = '1';
    }

    checkString(new DERNumericString(new String(shortChars)), new DERNumericString(new String(longChars)));

    final Bytes shortBytes = ByteUtils.newBytes((byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e');
    final BytesBuilder longBytes = ByteUtils.newBytesBuilder();

    for (int i = 0; i != longChars.length; i++) {
      longBytes.write((byte) 'X');
    }

    checkString(new DERUniversalString(shortBytes), new DERUniversalString(longBytes.build()));

  }

  private void checkString(final ASN1String shortString, final ASN1String longString)
      throws IOException {
    final ASN1String short2 = (ASN1String) ASN1Primitive.fromBytes(((ASN1Primitive) shortString).getEncoded());

    if (!shortString.toString().equals(short2.toString())) {
      fail(short2.getClass().getName() + " shortBytes result incorrect");
    }

    final ASN1String long2 = (ASN1String) ASN1Primitive.fromBytes(((ASN1Primitive) longString).getEncoded());

    if (!longString.toString().equals(long2.toString())) {
      fail(long2.getClass().getName() + " longBytes result incorrect");
    }
  }

}

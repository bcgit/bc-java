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


import static com.github.gv2011.testutil.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Ignore;
import org.junit.Test;

import com.github.gv2011.asn1.util.encoders.Hex;
import com.github.gv2011.asn1.util.test.SimpleTest;
import com.github.gv2011.util.bytes.Bytes;

public class DERApplicationSpecificTest
    extends SimpleTest
{
    private static final Bytes impData = Hex.decode("430109");

    private static final Bytes certData = Hex.decode(
        "7F218201897F4E8201495F290100420E44454356434145504153533030317F49"
      + "81FD060A04007F00070202020202811CD7C134AA264366862A18302575D1D787"
      + "B09F075797DA89F57EC8C0FF821C68A5E62CA9CE6C1C299803A6C1530B514E18"
      + "2AD8B0042A59CAD29F43831C2580F63CCFE44138870713B1A92369E33E2135D2"
      + "66DBB372386C400B8439040D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C"
      + "1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D376"
      + "1402CD851CD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A793"
      + "9F863904393EE8E06DB6C7F528F8B4260B49AA93309824D92CDB1807E5437EE2"
      + "E26E29B73A7111530FA86B350037CB9415E153704394463797139E148701015F"
      + "200E44454356434145504153533030317F4C0E060904007F0007030102015301"
      + "C15F25060007000400015F24060009000400015F37384CCF25C59F3612EEE188"
      + "75F6C5F2E2D21F0395683B532A26E4C189B71EFE659C3F26E0EB9AEAE9986310"
      + "7F9B0DADA16414FFA204516AEE2B");

    private final static Bytes sampleData = Hex.decode(
        "613280020780a106060456000104a203020101a305a103020101be80288006025101020109a080b2800a01000000000000000000");

    @Override
    public String getName()
    {
        return "DERApplicationSpecific";
    }

    private void testTaggedObject()throws Exception{
        // boolean explicit, int tagNo, ASN1Encodable obj
        boolean explicit = false;

        // Type1 ::= VisibleString
        final DERVisibleString type1 = new DERVisibleString("Jones");
        assertThat(type1.getEncoded(), is(Hex.decode("1A054A6F6E6573")));

        // Type2 ::= [APPLICATION 3] IMPLICIT Type1
        explicit = false;
        final DERApplicationSpecific type2 = new DERApplicationSpecific(explicit, 3, type1);
        // type2.isConstructed()
        assertThat(type1.getEncoded(), is(Hex.decode("1A054A6F6E6573")));
        if (!Hex.decode("43054A6F6E6573").equals(type2.getEncoded()))
        {
            fail("ERROR: expected value doesn't match!");
        }

        // Type3 ::= [2] Type2
        explicit = true;
        final DERTaggedObject type3 = new DERTaggedObject(explicit, 2, type2);
        assertThat(type3.getEncoded(), is(Hex.decode("A20743054A6F6E6573")));

        // Type4 ::= [APPLICATION 7] IMPLICIT Type3
        explicit = false;
        final DERApplicationSpecific type4 = new DERApplicationSpecific(explicit, 7, type3);
        assertThat(type4.getEncoded(), is(Hex.decode("670743054A6F6E6573")));

        // Type5 ::= [2] IMPLICIT Type2
        explicit = false;
        final DERTaggedObject type5 = new DERTaggedObject(explicit, 2, type2);
        // type5.isConstructed()
        assertThat(type5.getEncoded(), is(Hex.decode("82054A6F6E6573")));
    }

    @Test
    @Ignore //TODO check
    @Override
    public void performTest()throws Exception{
        testTaggedObject();

        final DERApplicationSpecific appSpec = (DERApplicationSpecific)ASN1Primitive.fromBytes(sampleData);

        if (1 != appSpec.getApplicationTag())
        {
            fail("wrong tag detected");
        }

        final ASN1Integer value = new ASN1Integer(9);

        final DERApplicationSpecific tagged = new DERApplicationSpecific(false, 3, value);

        assertThat("implicit encoding failed", tagged.getEncoded(), is(impData));

        final ASN1Integer recVal = (ASN1Integer)tagged.getObject(BERTags.INTEGER);

        assertThat("implicit read back failed", recVal, is(value));

        final DERApplicationSpecific certObj = (DERApplicationSpecific)
        ASN1Primitive.fromBytes(certData);

        assertThat("parsing of certificate data failed", certObj.isConstructed(), is(false));
        assertThat("parsing of certificate data failed", certObj.getApplicationTag(), is(33));

        final Bytes encoded = certObj.getEncoded(ASN1Encoding.DER);

        assertThat("re-encoding of certificate data failed", encoded, is(certData));
    }

}

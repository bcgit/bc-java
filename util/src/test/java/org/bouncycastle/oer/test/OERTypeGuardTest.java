package org.bouncycastle.oer.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.OEROptional;
import org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncrypted;
import org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataEncryptedUnicast;
import org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT32;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;
import org.bouncycastle.util.BigIntegers;

/**
 * The identity fast path in the OER getInstance factories has to test the type it returns.
 */
public class OERTypeGuardTest
    extends TestCase
{
    public void testUINT32GetInstance()
    {
        UINT32 uint32 = new UINT32(7);

        assertSame(uint32, UINT32.getInstance(uint32));
        assertEquals(BigInteger.valueOf(7), UINT32.getInstance(new ASN1Integer(7)).getValue());

        // a UINT8 is a sibling of UINT32 under UintBase, not a UINT32
        try
        {
            UINT32.getInstance(new UINT8(7));
            fail("UINT8 accepted as UINT32");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void testVersionGetInstance()
    {
        Version version = new Version(1);

        assertSame(version, Version.getInstance(version));
        assertEquals(BigIntegers.ONE, Version.getInstance(new ASN1Integer(1)).getVersion());

        try
        {
            Version.getInstance(new UINT8(1));
            fail("UINT8 accepted as Version");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public void testEtsiTs103097DataEncryptedUnicastGetInstance()
    {
        Ieee1609Dot2Content content = Ieee1609Dot2Content.unsecuredData(new byte[]{1, 2, 3});

        EtsiTs103097DataEncryptedUnicast unicast = new EtsiTs103097DataEncryptedUnicast(content);

        assertSame(unicast, EtsiTs103097DataEncryptedUnicast.getInstance(unicast));

        // EtsiTs103097DataEncrypted is a sibling under EtsiTs103097Data, so it has to be decoded
        // rather than cast
        EtsiTs103097DataEncrypted encrypted = new EtsiTs103097DataEncrypted(content);

        assertEquals(encrypted, EtsiTs103097DataEncryptedUnicast.getInstance(encrypted));
    }

    public void testOEROptionalGetObject()
    {
        ASN1Integer value = new ASN1Integer(3);

        assertSame(value, OEROptional.getInstance(value).getObject(ASN1Integer.class));

        // ASN1Encodable has no getInstance, so only the cast path can satisfy this
        assertSame(value, OEROptional.getValue(ASN1Encodable.class, value));
    }
}

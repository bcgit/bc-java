package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.util.test.SimpleTest;

import java.math.BigInteger;

public abstract class ASN1UnitTest
    extends SimpleTest
{
    protected void checkMandatoryField(String name, ASN1Encodable expected, ASN1Encodable present)
    {
        if (!expected.equals(present))
        {
            fail(name + " field doesn't match.");
        }
    }

    protected void checkMandatoryField(String name, String expected, String present)
    {
        if (!expected.equals(present))
        {
            fail(name + " field doesn't match.");
        }
    }

    protected void checkMandatoryField(String name, byte[] expected, byte[] present)
    {
        if (!areEqual(expected, present))
        {
            fail(name + " field doesn't match.");
        }
    }

    protected void checkMandatoryField(String name, int expected, int present)
    {
        if (expected != present)
        {
            fail(name + " field doesn't match.");
        }
    }

    protected void checkOptionalField(String name, ASN1Encodable expected, ASN1Encodable present)
    {
        if (expected != null)
        {
            if (!expected.equals(present))
            {
                fail(name + " field doesn't match.");
            }
        }
        else if (present != null)
        {
            fail(name + " field found when none expected.");
        }
    }

    protected void checkOptionalField(String name, String expected, String present)
    {
        if (expected != null)
        {
            if (!expected.equals(present))
            {
                fail(name + " field doesn't match.");
            }
        }
        else if (present != null)
        {
            fail(name + " field found when none expected.");
        }
    }

    protected void checkOptionalField(String name, BigInteger expected, BigInteger present)
    {
        if (expected != null)
        {
            if (!expected.equals(present))
            {
                fail(name + " field doesn't match.");
            }
        }
        else if (present != null)
        {
            fail(name + " field found when none expected.");
        }
    }


}

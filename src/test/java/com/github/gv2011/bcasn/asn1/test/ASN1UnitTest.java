package com.github.gv2011.bcasn.asn1.test;

import java.math.BigInteger;

import com.github.gv2011.bcasn.ASN1Encodable;
import com.github.gv2011.bcasn.util.test.SimpleTest;

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

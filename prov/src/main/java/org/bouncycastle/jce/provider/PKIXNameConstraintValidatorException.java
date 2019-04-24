package org.bouncycastle.jce.provider;

public class PKIXNameConstraintValidatorException
    extends Exception
{
    public PKIXNameConstraintValidatorException(String msg)
    {
        super(msg);
    }

    public PKIXNameConstraintValidatorException(String msg, Throwable e)
    {
        super(msg, e);
    }
}

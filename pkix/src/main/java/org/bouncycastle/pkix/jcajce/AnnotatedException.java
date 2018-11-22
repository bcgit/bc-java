package org.bouncycastle.pkix.jcajce;

class AnnotatedException
    extends Exception
{
    private Throwable _underlyingException;

    public AnnotatedException(String string, Throwable e)
    {
        super(string);

        _underlyingException = e;
    }

    public AnnotatedException(String string)
    {
        this(string, null);
    }

    public Throwable getCause()
    {
        return _underlyingException;
    }
}

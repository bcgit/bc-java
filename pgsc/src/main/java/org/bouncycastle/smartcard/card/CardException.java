package org.bouncycastle.smartcard.card;

public class CardException
        extends Exception
{
    public CardException()
    {
        super();
    }

    public CardException(String message)
    {
        super(message);
    }

    public CardException(Throwable cause)
    {
        super(cause);
    }

    public CardException(String message, Throwable cause)
    {
        super(message, cause);
    }
}

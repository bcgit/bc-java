package org.bouncycastle.cms;

public class PasswordRecipientId
    extends RecipientId
{
    /**
     * Construct a recipient ID of the password type.
     */
    public PasswordRecipientId()
    {
        super(password);
    }

    public int hashCode()
    {
        return password;
    }

    public boolean equals(
        Object o)
    {
        return o instanceof PasswordRecipientId;
    }

    public Object clone()
    {
        return new PasswordRecipientId();
    }

    public boolean match(Object obj)
    {
        return obj instanceof PasswordRecipientInformation;
    }
}

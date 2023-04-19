package org.bouncycastle.mail.smime.validator;

import org.bouncycastle.pkix.util.ErrorBundle;
import org.bouncycastle.pkix.util.LocalizedException;

public class SignedMailValidatorException extends LocalizedException
{

    public SignedMailValidatorException(ErrorBundle errorMessage, Throwable throwable)
    {
        super(errorMessage, throwable);
    }

    public SignedMailValidatorException(ErrorBundle errorMessage)
    {
        super(errorMessage);
    }
    
}

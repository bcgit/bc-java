package org.bouncycastle.jcajce.provider.keystore.util;

import java.io.IOException;
import java.security.KeyStore;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class ParameterUtil
{
    public static char[] extractPassword(KeyStore.LoadStoreParameter bcParam)
        throws IOException
    {
        KeyStore.ProtectionParameter protParam = bcParam.getProtectionParameter();

        if (protParam == null)
        {
            return null;
        }
        else if (protParam instanceof KeyStore.PasswordProtection)
        {
            return ((KeyStore.PasswordProtection)protParam).getPassword();
        }
        else if (protParam instanceof KeyStore.CallbackHandlerProtection)
        {
            CallbackHandler handler = ((KeyStore.CallbackHandlerProtection)protParam).getCallbackHandler();

            PasswordCallback passwordCallback = new PasswordCallback("password: ", false);

            try
            {
                handler.handle(new Callback[]{passwordCallback});

                return passwordCallback.getPassword();
            }
            catch (UnsupportedCallbackException e)
            {
                throw new IllegalArgumentException("PasswordCallback not recognised: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new IllegalArgumentException(
                "no support for protection parameter of type " + protParam.getClass().getName());
        }
    }
}

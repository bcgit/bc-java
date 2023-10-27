package org.bouncycastle.tls.injection.sigalgs;

import org.bouncycastle.tls.crypto.Tls13Verifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.security.*;

public class MyTls13Verifier
        implements Tls13Verifier
{
    private final PublicKey publicKey;
    private final SignatureSpi verifier;

    private ByteArrayOutputStream os = new ByteArrayOutputStream();

    public MyTls13Verifier(PublicKey publicKey, SignatureSpi verifier)
    {
        this.publicKey = publicKey;
        this.verifier = verifier;
    }

    private Method findDirectOrInheritedMethod(Class c, String methodName, Class... args) {
        Method m = null;
        while (c!=null) {
            for (Method mm : c.getDeclaredMethods()) {
                // this is an optimization: we don't check all arg types, just their number
                // (for SignatureSpi-s that's sufficient)
                if (mm.getName().equals(methodName) && (args.length == mm.getParameterTypes().length))
                    m = mm;
            }
            if (m!=null)
                break;
            c = c.getSuperclass();
        }
        m.setAccessible(true);
        return m;
    }

    public final OutputStream getOutputStream() throws IOException
    {
        return os;
    }

    public final boolean verifySignature(byte[] signature) throws IOException
    {
        try
        {
            Class c = verifier.getClass();

            Method m = this.findDirectOrInheritedMethod(c, "engineInitVerify", PublicKey.class);
            m.invoke(verifier, publicKey);

            m = this.findDirectOrInheritedMethod(c, "engineUpdate", byte[].class, int.class, int.class);
            byte[] data = os.toByteArray();
            m.invoke(verifier, data, 0, data.length);

            m = this.findDirectOrInheritedMethod(c, "engineVerify", byte[].class);
            Object result = m.invoke(verifier, signature);

            return (boolean) result;
        }
        catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }

}

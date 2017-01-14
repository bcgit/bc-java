package org.bouncycastle.est.http;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class ESTHttpException
    extends Exception
{
    private final int statusCode;
    private final String message;
    private final InputStream body;

    public ESTHttpException(String message, int statusCode, String message1, InputStream body, int contentLength)
    {
        super(message);
        this.statusCode = statusCode;
        this.message = message1;

        byte[] b = new byte[8192];
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            int i = body.read(b);
            while (i >= 0)
            {

                if (contentLength > -1)
                {
                    if (bos.size() + i > contentLength)
                    {
                        i = contentLength - bos.size();
                        bos.write(b, 0, i);
                        break;
                    }
                    else
                    {
                        bos.write(b, 0, i);
                    }
                }
                else
                {
                    bos.write(b, 0, i);
                }
                i = body.read(b);
            }
            bos.flush();
            bos.close();
            this.body = new ByteArrayInputStream(bos.toByteArray());
            body.close();
        }
        catch (Exception ex)
        {
            throw new RuntimeException("Reading error body:" + ex.getMessage(), ex);
        }

    }


}

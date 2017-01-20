package org.bouncycastle.est.http;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class ESTHttpException
    extends Exception
{
    private final int statusCode;
    private final InputStream body;

    public ESTHttpException(String message, Throwable cause, int statusCode, InputStream body)
    {
        super(message, cause);
        this.statusCode = statusCode;
        this.body = body;
    }



    public ESTHttpException(String message, int statusCode, InputStream body, int contentLength)
    {
        super(message);
        this.statusCode = statusCode;

        if (body != null)
        {
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
        else
        {
            this.body = null;
        }
    }


}

package org.bouncycastle.est;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public class ESTException
        extends Exception
{
    private Throwable cause;
    private InputStream body;
    private int statusCode;


    public ESTException(String msg)
    {
        this(msg, null);
        cause = null;
        body = null;
        statusCode = 0;
    }

    public ESTException(String msg, Throwable cause)
    {
        super(msg);
        this.cause = cause;
        body = null;
        statusCode = 0;
    }


    public ESTException(String message, Throwable cause, int statusCode, InputStream body)
    {
        super(message, cause);
        this.statusCode = statusCode;
        this.body = body;
        this.cause = null;
    }


    public ESTException(String message, int statusCode, InputStream body, int contentLength)
    {
        super(message);
        this.statusCode = statusCode;
        this.cause = null;

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
                        } else
                        {
                            bos.write(b, 0, i);
                        }
                    } else
                    {
                        bos.write(b, 0, i);
                    }
                    i = body.read(b);
                }
                bos.flush();
                bos.close();
                this.body = new ByteArrayInputStream(bos.toByteArray());
                body.close();
            } catch (Exception ex)
            {
                throw new RuntimeException("Reading error body:" + ex.getMessage(), ex);
            }
        } else
        {
            this.body = null;
        }
    }

    public InputStream getBody()
    {
        return body;
    }

    public int getStatusCode()
    {
        return statusCode;
    }

    public Throwable getCause()
    {
        return cause;
    }
}

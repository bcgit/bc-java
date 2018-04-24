package org.bouncycastle.est;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Exception emitted by EST classes.
 */
public class ESTException
    extends IOException
{
    private Throwable cause;

    private InputStream body;
    private int statusCode;

    private static final long MAX_ERROR_BODY = 8192;

    public ESTException(String msg)
    {
        this(msg, null);
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
        super(message);
        this.cause = cause;
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
                    if (bos.size() + i > MAX_ERROR_BODY)
                    {
                        i = (int)MAX_ERROR_BODY - bos.size();
                        bos.write(b, 0, i);
                        break;
                    }
                    bos.write(b, 0, i);
                    i = body.read(b);
                }
                bos.flush();
                bos.close();
                this.body = new ByteArrayInputStream(bos.toByteArray());
                body.close();
            }
            catch (Exception ex)
            {
                // This is a best effort read, input stream could be dead by this point.
            }
        }
        else
        {
            this.body = null;
        }
    }

    public Throwable getCause()
    {
        return cause;
    }
    
    public String getMessage()
    {
        return super.getMessage() + " HTTP Status Code: " + statusCode;
    }

    public InputStream getBody()
    {
        return body;
    }

    public int getStatusCode()
    {
        return statusCode;
    }

}

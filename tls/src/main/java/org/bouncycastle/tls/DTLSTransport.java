package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InterruptedIOException;

public class DTLSTransport
    implements DatagramTransport
{
    private final DTLSRecordLayer recordLayer;

    DTLSTransport(DTLSRecordLayer recordLayer)
    {
        this.recordLayer = recordLayer;
    }

    public int getReceiveLimit()
        throws IOException
    {
        return recordLayer.getReceiveLimit();
    }

    public int getSendLimit()
        throws IOException
    {
        return recordLayer.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        return receive(buf, off, len, waitMillis, null);
    }

    public int receive(byte[] buf, int off, int len, int waitMillis, DTLSRecordCallback recordCallback)    
        throws IOException
    {
        if (null == buf)
        {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (off < 0 || off >= buf.length)
        {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        }
        if (len < 0 || len > buf.length - off)
        {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        }
        if (waitMillis < 0)
        {
            throw new IllegalArgumentException("'waitMillis' cannot be negative");
        }

        try
        {
            return recordLayer.receive(buf, off, len, waitMillis, recordCallback);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            if (AlertDescription.bad_record_mac == fatalAlert.getAlertDescription())
            {
                return -1;
            }

            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (InterruptedIOException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public int receivePending(byte[] buf, int off, int len)
        throws IOException
    {
        return receivePending(buf, off, len, null);
    }

    public int receivePending(byte[] buf, int off, int len, DTLSRecordCallback recordCallback)    
        throws IOException
    {
        if (null == buf)
        {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (off < 0 || off >= buf.length)
        {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        }
        if (len < 0 || len > buf.length - off)
        {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        }

        try
        {
            return recordLayer.receivePending(buf, off, len, recordCallback);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            if (AlertDescription.bad_record_mac == fatalAlert.getAlertDescription())
            {
                return -1;
            }

            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (InterruptedIOException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        if (null == buf)
        {
            throw new NullPointerException("'buf' cannot be null");
        }
        if (off < 0 || off >= buf.length)
        {
            throw new IllegalArgumentException("'off' is an invalid offset: " + off);
        }
        if (len < 0 || len > buf.length - off)
        {
            throw new IllegalArgumentException("'len' is an invalid length: " + len);
        }

        try
        {
            recordLayer.send(buf, off, len);
        }
        catch (TlsFatalAlert fatalAlert)
        {
            recordLayer.fail(fatalAlert.getAlertDescription());
            throw fatalAlert;
        }
        catch (InterruptedIOException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw e;
        }
        catch (RuntimeException e)
        {
            recordLayer.fail(AlertDescription.internal_error);
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }

    public void close()
        throws IOException
    {
        recordLayer.close();
    }
}

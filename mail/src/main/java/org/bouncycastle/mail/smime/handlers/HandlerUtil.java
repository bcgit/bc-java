package org.bouncycastle.mail.smime.handlers;

import java.awt.datatransfer.DataFlavor;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;

import org.bouncycastle.mail.smime.SMIMEStreamingProcessor;

class HandlerUtil
{

    static void writeFromInputStream(InputStream obj, OutputStream os)
        throws IOException
    {
        int         b;
        InputStream in = obj;

        if (!(in instanceof BufferedInputStream))
        {
            in = new BufferedInputStream(in);
        }

        while ((b = in.read()) >= 0)
        {
            os.write(b);
        }

        in.close();
    }

    static void writeFromBarrInputStreamSMIMESTreamProcessor(Object obj, OutputStream os)
        throws IOException
    {
        if(obj instanceof byte[])
        {
            os.write((byte[])obj);
        }
        else if (obj instanceof InputStream)
        {
            writeFromInputStream((InputStream)obj, os);
        }
        else if (obj instanceof SMIMEStreamingProcessor)
        {
            SMIMEStreamingProcessor processor = (SMIMEStreamingProcessor)obj;

            processor.write(os);
        }
        else
        {
            throw new IOException("unknown object in writeTo " + obj);
        }
    }

    static void writeFromMimeBodyPart(MimeBodyPart obj, OutputStream os)
        throws IOException
    {
        try
        {
            obj.writeTo(os);
        }
        catch (MessagingException ex)
        {
            throw new IOException(ex.getMessage());
        }
    }

    static Object getTransferData(DataContentHandler handler, ActivationDataFlavor adf, DataFlavor df, DataSource ds)
        throws IOException
    {
        if (adf.equals(df))
        {
            return handler.getContent(ds);
        }
        else
        {
            return null;
        }
    }
}

package org.bouncycastle.mail.smime.handlers;

import java.awt.datatransfer.DataFlavor;
import java.io.IOException;
import java.io.OutputStream;

import javax.activation.ActivationDataFlavor;
import javax.activation.DataContentHandler;
import javax.activation.DataSource;
import javax.mail.internet.MimeBodyPart;

public class PKCS7ContentHandler 
    implements DataContentHandler 
{
    private final ActivationDataFlavor _adf;
    private final DataFlavor[]         _dfs;
    
    PKCS7ContentHandler(
        ActivationDataFlavor adf,
        DataFlavor[]         dfs)
    {
        _adf = adf;
        _dfs = dfs;
    }

    public Object getContent(
        DataSource ds)
        throws IOException
    {
        return ds.getInputStream();
    }
    
    public Object getTransferData(
        DataFlavor df, 
        DataSource ds) 
        throws IOException 
    {
        return HandlerUtil.getTransferData(this, _adf, df, ds);
    }
    
    public DataFlavor[] getTransferDataFlavors() 
    {
        return _dfs;
    }
    
    public void writeTo(
        Object obj, 
        String mimeType,
        OutputStream os) 
        throws IOException 
    {
        if (obj instanceof MimeBodyPart) 
        {
            HandlerUtil.writeFromMimeBodyPart((MimeBodyPart)obj, os);
        }
        else
        {
            HandlerUtil.writeFromBarrInputStreamSMIMESTreamProcessor(obj, os);
        }
    }
}

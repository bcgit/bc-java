package org.bouncycastle.mail.smime.handlers;

import java.awt.datatransfer.DataFlavor;

import jakarta.activation.ActivationDataFlavor;
import jakarta.mail.internet.MimeBodyPart;

public class pkcs7_mime 
    extends PKCS7ContentHandler
{
    private static final ActivationDataFlavor ADF = new ActivationDataFlavor(MimeBodyPart.class, "application/pkcs7-mime", "Encrypted Data");
    private static final ActivationDataFlavor[]         DFS = new ActivationDataFlavor[] { ADF };
    
    public pkcs7_mime()
    {
        super(ADF, DFS);
    }
}

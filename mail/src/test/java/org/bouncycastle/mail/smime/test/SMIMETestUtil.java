package org.bouncycastle.mail.smime.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import java.security.Security;

public class SMIMETestUtil
{
    public static final boolean DEBUG = true;

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    /*  
     *  
     *  MAIL
     *  
     */

    public static MimeBodyPart makeMimeBodyPart(String msg)
            throws MessagingException
    {

        MimeBodyPart _mbp = new MimeBodyPart();
        _mbp.setText(msg);
        return _mbp;
    }

    public static MimeBodyPart makeMimeBodyPart(MimeMultipart mm)
            throws MessagingException
    {

        MimeBodyPart _mbp = new MimeBodyPart();
        _mbp.setContent(mm, mm.getContentType());
        return _mbp;
    }

    public static MimeMultipart makeMimeMultipart(String msg1, String msg2)
            throws MessagingException
    {

        MimeMultipart _mm = new MimeMultipart();
        _mm.addBodyPart(makeMimeBodyPart(msg1));
        _mm.addBodyPart(makeMimeBodyPart(msg2));

        return _mm;
    }
}

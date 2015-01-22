package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

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

    public static void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b)
        throws IOException, MessagingException
    {
        ByteArrayOutputStream _baos = new ByteArrayOutputStream();
        a.writeTo(_baos);
        _baos.close();
        byte[] _msgBytes = _baos.toByteArray();
        _baos = new ByteArrayOutputStream();
        b.writeTo(_baos);
        _baos.close();
        byte[] _resBytes = _baos.toByteArray();

        TestCase.assertEquals(true, Arrays.areEqual(_msgBytes, _resBytes));
    }

    public static void verifyMessageBytes(MimeMessage a, MimeBodyPart b)
        throws IOException, MessagingException
    {
        ByteArrayOutputStream _baos = new ByteArrayOutputStream();
        a.writeTo(_baos);
        _baos.close();
        byte[] _msgBytes = _baos.toByteArray();
        _baos = new ByteArrayOutputStream();
        b.writeTo(_baos);
        _baos.close();
        byte[] _resBytes = _baos.toByteArray();

        TestCase.assertEquals(true, Arrays.areEqual(_msgBytes, _resBytes));
    }
}

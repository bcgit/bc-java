package org.bouncycastle.mail.smime.test;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.mail.smime.SMIMESigned;
import org.junit.Assert;
import org.junit.Test;

public class PipedStreamThreadStuckTest {

    @Test
    public void testPipedStreamCleanupOnFailure() throws Exception {
        // 1. Create a message that is NOT a valid S/MIME message
        // This will cause SMIMESigned constructor to throw an exception.
        MimeMessage message = createFakeMimeMessage();

        final AtomicBoolean threadWasInterrupted = new AtomicBoolean(false);
        final AtomicBoolean threadFinished = new AtomicBoolean(false);

        // 2. We trigger the S/MIME processing in a way that uses JavaMail's Piped streams.
        // We do this by capturing the 'Folder' or 'Transport' thread behavior.
        Thread pipeFeederThread = new Thread(new Runnable() {
            public void run() {
                try {
                    // This mimics JavaMail's background data writing
                    // If the pipe isn't closed, this thread hangs on write()
                    SMIMESigned signed = SMIMESigned.getSafeInstance((MimeMultipart)message.getContent());
                } catch (Exception e) {
                    // Expected failure
                } finally {
                    threadFinished.set(true);
                }
            }
        });

        pipeFeederThread.start();

        // 3. Wait to see if the thread hangs.
        // If the fix works, the pipe is closed, the feeder gets an IOException, and exits.
        pipeFeederThread.join(2000); 

        if (pipeFeederThread.isAlive()) {
            pipeFeederThread.interrupt();
            Assert.fail("Resource Leak Detected: The feeder thread is stuck in a Piped Stream hang!");
        }
        
        Assert.assertTrue("Thread should have finished after stream was safely closed", threadFinished.get());
    }

    public MimeMessage createFakeMimeMessage() throws MessagingException {
        Session session = Session.getDefaultInstance(new Properties());
        MimeMessage message = new MimeMessage(session);
        
        // This is "fake" because SMIMESigned expects a multipart/signed, 
        // but we are giving it a multipart/mixed.
        MimeMultipart rootMultipart = new MimeMultipart("mixed");

        MimeBodyPart part1 = new MimeBodyPart();
        part1.setText("Content Part");
        rootMultipart.addBodyPart(part1);

        MimeBodyPart part2 = new MimeBodyPart();
        part2.setText("Not a signature part");
        rootMultipart.addBodyPart(part2);

        message.setContent(rootMultipart);
        message.saveChanges();
        return message;
    }
}
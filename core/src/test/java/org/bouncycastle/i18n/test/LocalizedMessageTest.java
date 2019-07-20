package org.bouncycastle.i18n.test;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import junit.framework.TestCase;
import org.bouncycastle.i18n.LocaleString;
import org.bouncycastle.i18n.LocalizedMessage;
import org.bouncycastle.i18n.MissingEntryException;
import org.bouncycastle.i18n.filter.HTMLFilter;
import org.bouncycastle.i18n.filter.TrustedInput;

public class LocalizedMessageTest extends TestCase
{

    private static final String TEST_RESOURCE = "org.bouncycastle.i18n.test.I18nTestMessages";
    private static final String UTF8_TEST_RESOURCE = "org.bouncycastle.i18n.test.I18nUTF8TestMessages";

    /*
     * test message id's
     */
    private static final String timeTestId = "time";
    private static final String argsTestId = "arguments";
    private static final String localeTestId = "hello";
    private static final String missingTestId = "missing";
    private static final String filterTestId = "filter";
    private static final String utf8TestId = "utf8";

    /*
     * Test method for 'org.bouncycastle.i18n.LocalizedMessage.getEntry(String,
     * Locale, TimeZone)'
     */
    public void testGetEntry()
    {
        LocalizedMessage msg;

        // test different locales
        msg = new LocalizedMessage(TEST_RESOURCE, localeTestId);
        assertEquals("Hello world.", msg.getEntry("text", Locale.ENGLISH,
                TimeZone.getDefault()));
        assertEquals("Hallo Welt.", msg.getEntry("text", Locale.GERMAN,
                TimeZone.getDefault()));

        // test arguments
        Object[] args = new Object[] { "Nobody" };
        msg = new LocalizedMessage(TEST_RESOURCE, argsTestId, args);
        assertEquals("My name is Nobody.", msg.getEntry("text", Locale.ENGLISH,
                TimeZone.getDefault()));
        assertEquals("Mein Name ist Nobody.", msg.getEntry("text",
                Locale.GERMAN, TimeZone.getDefault()));

        // test timezones
        // test date 17. Aug. 13:12:00 GMT
        Date testDate = new Date(1155820320000l);
        args = new Object[] { new TrustedInput(testDate) };
        msg = new LocalizedMessage(TEST_RESOURCE, timeTestId, args);
        assertEquals("It's 1:12:00 PM GMT at Aug 17, 2006.", msg.getEntry(
                "text", Locale.ENGLISH, TimeZone.getTimeZone("GMT"))
            .replace("Greenwich Mean Time", "GMT"));
        // NOTE: Older JDKs appear to use '.' as the time separator for German locale
        assertEquals("Es ist 13:12 Uhr GMT am 17.08.2006.", msg.getEntry(
                "text", Locale.GERMAN, TimeZone.getTimeZone("GMT"))
            .replace("13.12", "13:12")
            .replace(":00 Mittlere Greenwich-Zeit", " Uhr GMT"));

        // test time with filter
        args = new Object[] { new TrustedInput(testDate) };
        msg = new LocalizedMessage(TEST_RESOURCE, timeTestId, args);
        msg.setFilter(new HTMLFilter());
        assertEquals("It's 1:12:00 PM GMT at Aug 17, 2006.", msg.getEntry(
                "text", Locale.ENGLISH, TimeZone.getTimeZone("GMT"))
                   .replace("Greenwich Mean Time", "GMT"));
        // NOTE: Older JDKs appear to use '.' as the time separator for German locale
        assertEquals("Es ist 13:12 Uhr GMT am 17.08.2006.", msg.getEntry(
                "text", Locale.GERMAN, TimeZone.getTimeZone("GMT"))
            .replace("13.12", "13:12")
        .replace(":00 Mittlere Greenwich-Zeit", " Uhr GMT"));
        
        // test number
        args = new Object[] { new TrustedInput(new Float(0.2))  };
        msg = new LocalizedMessage(TEST_RESOURCE, "number", args);
        assertEquals("20%", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));

        // test filters
        String untrusted = "<script>doBadThings()</script>";
        args = new Object[] { untrusted };
        msg = new LocalizedMessage(TEST_RESOURCE,filterTestId,args);
        msg.setFilter(new HTMLFilter());
        assertEquals("The following part should contain no HTML tags: "
                + "&#60script&#62doBadThings&#40&#41&#60/script&#62",
                msg.getEntry("text",Locale.ENGLISH, TimeZone.getDefault()));
        
        // test missing entry
        msg = new LocalizedMessage(TEST_RESOURCE, missingTestId);
        try
        {
            String text = msg.getEntry("text", Locale.UK, TimeZone
                    .getDefault());
            fail();
        }
        catch (MissingEntryException e)
        {
//            System.out.println(e.getDebugMsg());
        }
        
        // test missing entry
        try
        {
            URLClassLoader cl = URLClassLoader.newInstance(new URL[] {new URL("file:///nonexistent/")});
            msg = new LocalizedMessage(TEST_RESOURCE, missingTestId);
            msg.setClassLoader(cl);
            try
            {
                String text = msg.getEntry("text", Locale.UK, TimeZone
                        .getDefault());
                fail();
            }
            catch (MissingEntryException e)
            {
//                System.out.println(e.getDebugMsg());
            }
        }
        catch (MalformedURLException e)
        {
            
        }
        
        // test utf8
        // TODO: as of Java 11 this no longer works... read of the properties appears to corrupt
//        try
//        {
////            String expectedUtf8 = "some umlauts äöüèéà";
//            String expectedUtf8 = Strings.fromUTF8ByteArray(Hex.decode("736f6d6520756d6c6175747320c3a4c3b6c3bcc3a8c3a9c3a0"));
//            msg = new LocalizedMessage(UTF8_TEST_RESOURCE, utf8TestId, "UTF-8");
//            assertEquals(expectedUtf8, msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));
//        }
//        catch (UnsupportedEncodingException e)
//        {
//
//        }

    }
    
    public void testLocalizedArgs()
    {
        LocaleString ls = new LocaleString(TEST_RESOURCE, "name");
        
        // without filter
        Object[] args = new Object[] { ls };
        LocalizedMessage msg = new LocalizedMessage(TEST_RESOURCE, argsTestId, args);
        assertEquals("My name is John.", msg.getEntry("text", Locale.ENGLISH,
                TimeZone.getDefault()));
        assertEquals("Mein Name ist Hans.", msg.getEntry("text",
                Locale.GERMAN, TimeZone.getDefault()));
        
        // with filter
        msg.setFilter(new HTMLFilter());
        assertEquals("My name is John.", msg.getEntry("text", Locale.ENGLISH,
                TimeZone.getDefault()));
        assertEquals("Mein Name ist Hans.", msg.getEntry("text",
                Locale.GERMAN, TimeZone.getDefault()));
        
        // add extra args
        LocaleString lsExtra = new LocaleString(TEST_RESOURCE, "hello.text");
        msg.setExtraArguments(new Object[] {" ", lsExtra});
        assertEquals("My name is John. Hello world.", msg.getEntry("text", Locale.ENGLISH,
                TimeZone.getDefault()));
        assertEquals("Mein Name ist Hans. Hallo Welt.", msg.getEntry("text",
                Locale.GERMAN, TimeZone.getDefault()));
        
        // missing localized arg
        try
        {
            ls = new LocaleString(TEST_RESOURCE, "noname");
            args = new Object[] { ls };
            msg = new LocalizedMessage(TEST_RESOURCE, argsTestId, args);
            msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault());
            fail();
        }
        catch (MissingEntryException e)
        {
            assertEquals("Can't find entry noname in resource file org.bouncycastle.i18n.test.I18nTestMessages.", e.getMessage());
        }
    }

}

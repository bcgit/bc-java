package org.bouncycastle.cert.test;

import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.dane.DANECertificateFetcher;
import org.bouncycastle.cert.dane.DANEEntry;
import org.bouncycastle.cert.dane.DANEEntryFactory;
import org.bouncycastle.cert.dane.DANEEntryFetcher;
import org.bouncycastle.cert.dane.DANEEntryFetcherFactory;
import org.bouncycastle.cert.dane.DANEEntrySelector;
import org.bouncycastle.cert.dane.DANEEntrySelectorFactory;
import org.bouncycastle.cert.dane.DANEEntryStore;
import org.bouncycastle.cert.dane.DANEEntryStoreBuilder;
import org.bouncycastle.cert.dane.DANEException;
import org.bouncycastle.cert.dane.TruncatingDigestCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class DANETest
    extends SimpleTest
{
    byte[]  randomCert = Base64.decode(
            "MIIDbDCCAtWgAwIBAgIBADANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx"
                + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY"
                + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB"
                + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ"
                + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU1MzNaFw0wMTA2"
                + "MDIwNzU1MzNaMIG3MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW"
                + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM"
                + "dGQxHjAcBgNVBAsTFUNlcnRpZmljYXRlIEF1dGhvcml0eTEVMBMGA1UEAxMMQ29u"
                + "bmVjdCA0IENBMSgwJgYJKoZIhvcNAQkBFhl3ZWJtYXN0ZXJAY29ubmVjdDQuY29t"
                + "LmF1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgs5ptNG6Qv1ZpCDuUNGmv"
                + "rhjqMDPd3ri8JzZNRiiFlBA4e6/ReaO1U8ASewDeQMH6i9R6degFdQRLngbuJP0s"
                + "xcEE+SksEWNvygfzLwV9J/q+TQDyJYK52utb++lS0b48A1KPLwEsyL6kOAgelbur"
                + "ukwxowprKUIV7Knf1ajetQIDAQABo4GFMIGCMCQGA1UdEQQdMBuBGXdlYm1hc3Rl"
                + "ckBjb25uZWN0NC5jb20uYXUwDwYDVR0TBAgwBgEB/wIBADA2BglghkgBhvhCAQ0E"
                + "KRYnbW9kX3NzbCBnZW5lcmF0ZWQgY3VzdG9tIENBIGNlcnRpZmljYXRlMBEGCWCG"
                + "SAGG+EIBAQQEAwICBDANBgkqhkiG9w0BAQQFAAOBgQCsGvfdghH8pPhlwm1r3pQk"
                + "msnLAVIBb01EhbXm2861iXZfWqGQjrGAaA0ZpXNk9oo110yxoqEoSJSzniZa7Xtz"
                + "soTwNUpE0SLHvWf/SlKdFWlzXA+vOZbzEv4UmjeelekTm7lc01EEa5QRVzOxHFtQ"
                + "DhkaJ8VqOMajkQFma2r9iA==");

    public String getName()
    {
        return "DANETest";
    }

    private void shouldCreateDANEEntry()
        throws IOException, DANEException
    {
        DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));

        DANEEntry entry = daneEntryFactory.createEntry("test@test.com", new X509CertificateHolder(randomCert));

        if (!DANEEntry.isValidCertificate(entry.getRDATA()))
        {
            fail("encoding error in RDATA");
        }

        if (!"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.com".equals(entry.getDomainName()))
        {
            fail("domain name associated with entry wrong");
        }

        byte[] rdata = entry.getRDATA();
        byte[] certData = new byte[rdata.length - 3];

        System.arraycopy(rdata, 3, certData, 0, certData.length);

        if (!Arrays.areEqual(certData, randomCert))
        {
            fail("certificate encoding does not match");
        }
    }

    private void shouldValidateCertificateUsageRange()
        throws IOException, DANEException
    {
        DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));

        DANEEntry entry = daneEntryFactory.createEntry("test@test.com", new X509CertificateHolder(randomCert));

        byte[] rdata = entry.getRDATA();

        // each of the assigned certificate usages 0..3 (with selector/matching-type 0) must validate.
        for (int usage = 0; usage <= 3; usage++)
        {
            rdata[0] = (byte)usage;

            if (!DANEEntry.isValidCertificate(rdata))
            {
                fail("certificate usage " + usage + " should be valid");
            }
        }

        // an unassigned positive certificate usage (4..127) must not validate.
        rdata[0] = (byte)4;
        if (DANEEntry.isValidCertificate(rdata))
        {
            fail("certificate usage 4 should not be valid");
        }

        rdata[0] = (byte)127;
        if (DANEEntry.isValidCertificate(rdata))
        {
            fail("certificate usage 127 should not be valid");
        }

        // an unassigned certificate usage with the high bit set (128..255, i.e. negative as a byte) must not validate.
        rdata[0] = (byte)0xFF;
        if (DANEEntry.isValidCertificate(rdata))
        {
            fail("certificate usage 255 should not be valid");
        }

        rdata[0] = (byte)0x80;
        if (DANEEntry.isValidCertificate(rdata))
        {
            fail("certificate usage 128 should not be valid");
        }

        // a record shorter than the three flag bytes (or null) must not validate, and must not throw
        if (DANEEntry.isValidCertificate(null)
            || DANEEntry.isValidCertificate(new byte[0])
            || DANEEntry.isValidCertificate(new byte[]{ 0 })
            || DANEEntry.isValidCertificate(new byte[]{ 0, 0 }))
        {
            fail("a record shorter than the flag bytes should not be valid");
        }
    }

    private void shouldSplitAddressOnLastAt()
        throws Exception
    {
        DANEEntrySelectorFactory selectorFactory = new DANEEntrySelectorFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));

        try
        {
            selectorFactory.createSelector("no-at-sign.test.com");
            fail("address without '@' accepted");
        }
        catch (DANEException e)
        {
            isEquals("email address has no '@'", e.getMessage());
        }

        // RFC 8162 sec. 3: enclosing quotes and backslash quoting are removed from the local-part before hashing.
        DANEEntrySelector selector = selectorFactory.createSelector("\"a@b\"@test.com");

        isEquals("7508d8b5018ea640b85269861a101203f0c26900555268e930025dac._smimecert.test.com", selector.getDomainName());

        selector = selectorFactory.createSelector("\"a\\@b\"@test.com");

        isEquals("7508d8b5018ea640b85269861a101203f0c26900555268e930025dac._smimecert.test.com", selector.getDomainName());

        // an unquoted local-part is hashed as is.
        isEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15._smimecert.test.com", selectorFactory.createSelector("test@test.com").getDomainName());

        // a selector does not match anything other than a DANEEntry.
        isTrue(!selector.match("\"a@b\"@test.com"));
    }

    private void shouldRejectRecordThatIsNotFullCertificate()
        throws Exception
    {
        DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));
        byte[] rdata = daneEntryFactory.createEntry("test@test.com", new X509CertificateHolder(randomCert)).getRDATA();

        // round trip of a valid record
        DANEEntry entry = new DANEEntry("x._smimecert.test.com", rdata);

        isTrue(Arrays.areEqual(rdata, entry.getRDATA()));

        byte[][] badRecords = new byte[][]{ new byte[0], new byte[]{ 3 }, new byte[]{ 3, 0 }, new byte[]{ 3, 0, 0 } };
        for (int i = 0; i != badRecords.length; i++)
        {
            try
            {
                new DANEEntry("x._smimecert.test.com", badRecords[i]);
                fail("record of length " + badRecords[i].length + " accepted");
            }
            catch (IOException e)
            {
                // expected
            }
        }

        // selector 1 (SubjectPublicKeyInfo) and matching type 1 (SHA-256) are not full certificate entries.
        byte[] spki = Arrays.clone(rdata);
        spki[1] = 1;
        byte[] hashed = Arrays.clone(rdata);
        hashed[2] = 1;
        byte[] usage = Arrays.clone(rdata);
        usage[0] = 4;
        byte[][] wrongFlags = new byte[][]{ spki, hashed, usage };
        for (int i = 0; i != wrongFlags.length; i++)
        {
            try
            {
                new DANEEntry("x._smimecert.test.com", wrongFlags[i]);
                fail("record with flags " + wrongFlags[i][0] + "/" + wrongFlags[i][1] + "/" + wrongFlags[i][2] + " accepted");
            }
            catch (IOException e)
            {
                isEquals("DANE record is not a full certificate entry", e.getMessage());
            }
        }
    }

    private void shouldKeepEveryEntryForAnAddress()
        throws Exception
    {
        DANEEntryFactory daneEntryFactory = new DANEEntryFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));
        X509CertificateHolder cert = new X509CertificateHolder(randomCert);

        // two SMIMEA records under one owner name, as for a user with a signing and an encryption certificate.
        final List records = new ArrayList();
        records.add(daneEntryFactory.createEntry("test@test.com", DANEEntry.CERT_USAGE_ACCEPT, cert));
        records.add(daneEntryFactory.createEntry("test@test.com", DANEEntry.CERT_USAGE_PKIX_VALIDATE, cert));
        records.add(daneEntryFactory.createEntry("other@test.com", cert));

        DANEEntryFetcherFactory fetcherFactory = new DANEEntryFetcherFactory()
        {
            public DANEEntryFetcher build(final String domainName)
            {
                return new DANEEntryFetcher()
                {
                    public List getEntries()
                    {
                        List matches = new ArrayList();
                        for (int i = 0; i != records.size(); i++)
                        {
                            DANEEntry entry = (DANEEntry)records.get(i);
                            if (entry.getDomainName().endsWith(domainName))
                            {
                                matches.add(entry);
                            }
                        }
                        return matches;
                    }
                };
            }
        };

        DANEEntryStore store = new DANEEntryStoreBuilder(fetcherFactory).build("test.com");

        isEquals(3, store.getMatches(null).size());
        isEquals(3, store.toCertificateStore().getMatches(null).size());

        DANEEntrySelector selector = new DANEEntrySelectorFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator())).createSelector("test@test.com");
        Collection matches = store.getMatches(selector);

        isEquals(2, matches.size());
        isTrue(matches.contains(records.get(0)) && matches.contains(records.get(1)));

        List certs = new DANECertificateFetcher(fetcherFactory, new TruncatingDigestCalculator(new SHA256DigestCalculator())).fetch("test@test.com");

        isEquals(2, certs.size());
        isEquals(1, new DANECertificateFetcher(fetcherFactory, new TruncatingDigestCalculator(new SHA256DigestCalculator())).fetch("other@test.com").size());
    }

    public void performTest()
        throws Exception
    {
         shouldCreateDANEEntry();
         shouldValidateCertificateUsageRange();
         shouldSplitAddressOnLastAt();
         shouldRejectRecordThatIsNotFullCertificate();
         shouldKeepEveryEntryForAnAddress();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new DANETest());
    }
}

package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test class for {@link PKIXNameConstraintValidator}.
 * <p>
 * The field testXYZ is the name to test.
 * <p>
 * The field testXYZIsConstraint must be tested if it is permitted and excluded.
 * <p>
 * The field testXYZIsNotConstraint must be tested if it is not permitted and
 * not excluded.
 * <p>
 * Furthermore there are tests for the intersection and union of test names.
 * 
 */
public class PKIXNameConstraintsTest
    extends SimpleTest
{

    private final static String testEmail = "test@abc.test.com";

    private final static String testEmailIsConstraint[] =
    { "test@abc.test.com", "abc.test.com", ".test.com" };

    private final static String testEmailIsNotConstraint[] =
    { ".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com" };

    private final static String email1[] =
    { "test@test.com", "test@test.com", "test@test.com", "test@abc.test.com",
            "test@test.com", "test@test.com", ".test.com", ".test.com",
            ".test.com", ".test.com", "test.com", "abc.test.com",
            "abc.test1.com", "test.com", "test.com", ".test.com" };

    private final static String email2[] =
    { "test@test.abc.com", "test@test.com", ".test.com", ".test.com",
            "test.com", "test1.com", "test@test.com", ".test.com",
            ".test1.com", "test.com", "test.com", ".test.com", ".test.com",
            "test1.com", ".test.com", "abc.test.com" };

    private final static String emailintersect[] =
    { null, "test@test.com", null, "test@abc.test.com", "test@test.com", null,
            null, ".test.com", null, null, "test.com", "abc.test.com", null,
            null, null, "abc.test.com" };

    private final static String emailunion[][] =
    {
    { "test@test.com", "test@test.abc.com" },
    { "test@test.com" },
    { "test@test.com", ".test.com" },
    { ".test.com" },
    { "test.com" },
    { "test@test.com", "test1.com" },
    { ".test.com", "test@test.com" },
    { ".test.com" },
    { ".test.com", ".test1.com" },
    { ".test.com", "test.com" },
    { "test.com" },
    { ".test.com" },
    { ".test.com", "abc.test1.com" },
    { "test1.com", "test.com" },
    { ".test.com", "test.com" },
    { ".test.com" } };

    private final static String[] dn1 =
    { "O=test org, OU=test org unit, CN=John Doe" };

    private final static String[] dn2 =
    { "O=test org, OU=test org unit" };

    private final static String[][] dnUnion =
    {
    { "O=test org, OU=test org unit" } };

    private final static String[] dnIntersection =
    { "O=test org, OU=test org unit, CN=John Doe" };

    // Note: In BC text conversion is ISO format - IETF starts at the back.
    private final static String testDN = "O=test org, OU=test org unit, CN=John Doe";

    private final static String testDNIsConstraint[] =
    {
        "O=test org, OU=test org unit",
        "O=test org, OU=test org unit, CN=John Doe",
    };

    private final static String testDNIsNotConstraint[] =
    {
        "O=test org, OU=test org unit, CN=John Doe2",
        "O=test org, OU=test org unit2",
        "O=test org, OU=test org unit, CN=John Doe, L=USA"
    };

    private final static String testDNS = "abc.test.com";

    private final static String testDNSIsConstraint[] =
    { "test.com", "abc.test.com", "test.com" };

    private final static String testDNSIsNotConstraint[] =
    { "wwww.test.com", "ww.test.com", "www.test.com" };

    private final static String dns1[] =
    { "www.test.de", "www.test1.de", "www.test.de" };

    private final static String dns2[] =
    { "test.de", "www.test.de", "www.test.de" };

    private final static String dnsintersect[] =
    { "www.test.de", null, "www.test.de" };

    private final static String dnsunion[][] =
    {
    { "test.de" },
    { "www.test1.de", "www.test.de" },
    { "www.test.de" } };

    private final static String testURI = "http://karsten:password@abc.test.com:8080";

    private final static String testURIIsConstraint[] =
    { "abc.test.com", ".test.com" };

    private final static String testURIIsNotConstraint[] =
    { "xyz.test.com", ".abc.test.com" };

    private final static String uri1[] =
    { "www.test.de", ".test.de", "test1.de", ".test.de" };

    private final static String uri2[] =
    { "test.de", "www.test.de", "test1.de", ".test.de" };

    private final static String uriintersect[] =
    { null, "www.test.de", "test1.de", ".test.de" };

    private final static String uriunion[][] =
    {
    { "www.test.de", "test.de" },
    { ".test.de" },
    { "test1.de" },
    { ".test.de" } };

    private final static byte[] testIP =

    { (byte) 192, (byte) 168, 1, 2 };

    private final static byte[][] testIPIsConstraint =
    {
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 4 } };

    private final static byte[][] testIPIsNotConstraint =
    {
    { (byte) 192, (byte) 168, 3, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 2 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 3 } };

    private final static byte[][] ip1 =
    {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ip2 =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFC, 3 },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ipintersect =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF }, null };

    private final static byte[][][] ipunion =
    {
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFE, (byte) 0xFF },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFC, 3 } },
            {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF } },
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 } } };

    public String getName()
    {
        return "PKIXNameConstraintsTest";
    }

    public void performTest() throws Exception
    {
        testConstraints(GeneralName.rfc822Name, testEmail,
            testEmailIsConstraint, testEmailIsNotConstraint, email1, email2,
            emailunion, emailintersect);
        testConstraints(GeneralName.dNSName, testDNS, testDNSIsConstraint,
            testDNSIsNotConstraint, dns1, dns2, dnsunion, dnsintersect);
        testConstraints(GeneralName.directoryName, testDN, testDNIsConstraint,
            testDNIsNotConstraint, dn1, dn2, dnUnion, dnIntersection);
        testConstraints(GeneralName.uniformResourceIdentifier, testURI,
            testURIIsConstraint, testURIIsNotConstraint, uri1, uri2, uriunion,
            uriintersect);
        testConstraints(GeneralName.iPAddress, testIP, testIPIsConstraint,
            testIPIsNotConstraint, ip1, ip2, ipunion, ipintersect);

        PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
        constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.directoryName, new X500Name(RFC4519Style.INSTANCE, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"))));
        constraintValidator.checkPermitted(new GeneralName(GeneralName.directoryName, new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US")));

        GeneralName name = new GeneralName(GeneralName.otherName, new OtherName(new ASN1ObjectIdentifier("1.1"), DERNull.INSTANCE));
        GeneralSubtree subtree = new GeneralSubtree(name);

        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(subtree);

        name = new GeneralName(GeneralName.otherName, new OtherName(new ASN1ObjectIdentifier("1.1"), DERNull.INSTANCE));
        subtree = new GeneralSubtree(name);

        validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(subtree);
        validator.addExcludedSubtree(subtree);

        try
        {
            validator.checkExcluded(name);
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            isEquals("OtherName is from an excluded subtree.", e.getMessage());
        }

        try
        {
            validator.checkPermitted(name);
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            fail(e.getMessage());
        }

        testTrailingDotBypass();
        testDirectoryNamePrefixBypass();
        testUriHostExtractionBypass();
        testIPv4MappedAddressBypass();
        testQuotedLocalPartEmailBypass();

        testSGP22LegacySerialNumber();
        testSGP22NameConstraints();
    }

    /**
     * RFC 1034 sec. 3.1 root-label trailing dot. A trailing '.' is legal in an rfc822Name, a dNSName
     * (RFC 5280 sec. 4.2.1.6) and a uniformResourceIdentifier host, and must be canonicalized away
     * uniformly across all three so it can't misalign the per-label compare and let a name escape an
     * excluded subtree.
     */
    private void testTrailingDotBypass() throws Exception
    {
        // rfc822Name: a trailing dot on the mail host must not escape the excluded bank.com subtree.
        isTrue("trailing-dot email must be caught by the excluded bank.com subtree",
            isExcluded(emailName("bank.com"), emailName("ceo@bank.com.")));

        // dNSName: exact and subdomain forms, including a dot-prefixed constraint.
        isTrue("exact host with a trailing dot must be caught",
            isExcluded(dnsName("example.com"), dnsName("example.com.")));
        isTrue("subdomain with a trailing dot must be caught",
            isExcluded(dnsName("example.com"), dnsName("foo.example.com.")));
        isTrue("subdomain with a trailing dot must be caught by a dot-prefixed constraint",
            isExcluded(dnsName(".example.com"), dnsName("foo.example.com.")));
        isTrue("a sibling domain must not be caught", !isExcluded(dnsName("example.com"), dnsName("notexample.com.")));

        // uniformResourceIdentifier: the host trailing dot is stripped like the dNSName path.
        isTrue("trailing-dot URI host must be caught by the excluded competitor.example subtree",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example./")));
    }

    /**
     * A tested rfc822Name with more than one '@' is ambiguous - a quoted local part may legally contain
     * '@' (RFC 5321 sec. 4.1.2), so the domain is after the LAST '@', not the first. Rather than split at
     * the first '@' into a wrong host that could evade a constraint, such a name is rejected fail-closed
     * when email constraints are present; with none, it is tolerated (strict-when-constrained).
     */
    private void testQuotedLocalPartEmailBypass() throws Exception
    {
        // A genuine evil.com mailbox with a quoted local part; a first-'@' split yields host b"@evil.com,
        // which would slip past the excluded evil.com subtree.
        isTrue("an ambiguous multi-'@' rfc822Name must be caught (fail-closed) by an excluded constraint",
            isExcluded(emailName("evil.com"), emailName("\"a@b\"@evil.com")));

        // The exact PoC vector from the feedback-crypto report: effective domain (after the last '@') is
        // excluded.example.com, but a first-'@' split compared evil.com"@excluded.example.com and missed it.
        isTrue("the reported quoted-local-part vector must be caught by the excluded subtree",
            isExcluded(emailName("excluded.example.com"), emailName("\"user@evil.com\"@excluded.example.com")));

        // Any multi-'@' tested name fails closed under a permitted constraint too.
        isTrue("an ambiguous multi-'@' rfc822Name must not satisfy a permitted constraint",
            !isPermitted(emailName("bank.com"), emailName("\"a@b\"@bank.com")));

        // Strict-when-constrained: with no email constraints in play, the ambiguous name is tolerated.
        try
        {
            PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
            validator.checkPermitted(emailName("\"a@b\"@evil.com"));
            validator.checkExcluded(emailName("\"a@b\"@evil.com"));
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            fail("an ambiguous email must be tolerated when no email constraints are present");
        }

        // A normal single-'@' address is unaffected.
        isTrue("a normal single-'@' address must not be affected",
            !isExcluded(emailName("evil.com"), emailName("user@safe.com")));

        // The safety valve restores the legacy lenient parsing: the ambiguous name is no longer rejected
        // (it falls back to the first-'@' split and simply fails to match, as it did before the fix).
        System.setProperty(Properties.X509_ALLOW_LENIENT_RFC822_NAME, "true");
        try
        {
            isTrue("the lenient valve must disable the ambiguity rejection",
                !isExcluded(emailName("evil.com"), emailName("\"a@b\"@evil.com")));
        }
        finally
        {
            System.getProperties().remove(Properties.X509_ALLOW_LENIENT_RFC822_NAME);
        }
    }

    /**
     * directoryName constraints must match as an INITIAL PREFIX of the subject (RFC 5280 sec.
     * 4.2.1.10 / 7.1), not as a subsequence at an arbitrary offset. Prepending an RDN ahead of the
     * permitted sequence must not satisfy the constraint.
     */
    private void testDirectoryNamePrefixBypass() throws Exception
    {
        GeneralName permittedDN = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prefixSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US"));
        GeneralName prependedSubject = new GeneralName(GeneralName.directoryName,
            new X500Name(RFC4519Style.INSTANCE, "cn=Valid DN nameConstraints EE Certificate Test1, ou=permittedSubtree1, o=Test Certificates 2011, c=US, o=Injected"));

        isTrue("prefix subject must be permitted", isPermitted(permittedDN, prefixSubject));
        isTrue("subject with an RDN prepended before the permitted sequence must NOT be permitted",
            !isPermitted(permittedDN, prependedSubject));
    }

    /**
     * uniformResourceIdentifier host-extraction edge cases (RFC 3986 sec. 3.2 authority). These
     * exercise <c>ExtractHostFromURL</c> indirectly: a bracketed IPv6 literal (whose ':' separators
     * must not be read as a port delimiter), userinfo stripping, and the path/query/fragment
     * terminator being applied BEFORE the userinfo '@' so an '@' in the path or fragment can't be
     * mistaken for a userinfo delimiter and swap in an attacker-chosen host.
     */
    private void testUriHostExtractionBypass() throws Exception
    {
        // Bracketed IPv6 host: the ':' inside the literal must not truncate at a phantom port, however
        // the port/userinfo are dressed up around it.
        isTrue("bracketed IPv6 host with a port must be caught by the excluded 2001:db8::1 subtree",
            isExcluded(uriName("2001:db8::1"), uriName("https://[2001:db8::1]:8443/x")));
        isTrue("bracketed IPv6 host without a port must be caught",
            isExcluded(uriName("2001:db8::1"), uriName("https://[2001:db8::1]/x")));
        isTrue("bracketed IPv6 host behind userinfo must be caught",
            isExcluded(uriName("2001:db8::1"), uriName("https://user:pw@[2001:db8::1]:8443/x")));

        // An '@' after the path/query/fragment terminator must NOT be read as userinfo; otherwise the
        // host would become the attacker-chosen authority after the '@' and escape the constraint.
        isTrue("'@' in the query must not be treated as userinfo",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example?u=x@evil.example")));
        isTrue("'@' in the fragment must not be treated as userinfo",
            isExcluded(uriName("competitor.example"), uriName("https://competitor.example#@evil.example")));

        // A genuine userinfo '@' before the host is still stripped.
        isTrue("userinfo before the host must be stripped",
            isExcluded(uriName("host.example"), uriName("https://user@host.example/")));

        // Sanity: an unrelated host is not caught (extraction isn't over-matching).
        isTrue("an unrelated URI host must not be caught",
            !isExcluded(uriName("competitor.example"), uriName("https://safe.example/")));
    }

    /**
     * IPv4-mapped IPv6 (RFC 4291 sec. 2.5.5.2, <c>::ffff:0:0/96</c>) iPAddress normalization. A SAN
     * that encodes an IPv4 address in the 16-byte mapped form must not slip past an 8-byte IPv4
     * constraint (or vice versa) via the address-family length mismatch; and a constraint whose mask
     * is narrower than /96 is a genuine IPv6 range that must not be collapsed to IPv4.
     */
    public void testIPv4MappedAddressBypass() throws Exception
    {
        // 192.0.2.0/24 as an 8-byte IPv4 constraint (address || mask).
        byte[] ipv4Cidr24 = bytes(new int[]{ 192, 0, 2, 0, 0xFF, 0xFF, 0xFF, 0x00 });

        // The same /24 as a 32-byte IPv4-mapped IPv6 constraint (all-ones across the /96 prefix).
        byte[] mappedCidr24 = bytes(new int[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 });

        // mapped SAN vs IPv4 constraint: caught (16-byte SAN normalizes to 4-byte 192.0.2.5).
        isTrue("IPv4-mapped SAN must be caught by the excluded IPv4 /24 constraint",
            isExcluded(ipName(ipv4Cidr24), ipName(ipv4Mapped(192, 0, 2, 5))));

        // IPv4 SAN vs mapped constraint: caught (32-byte constraint normalizes to the /24).
        isTrue("IPv4 SAN must be caught by the excluded IPv4-mapped /24 constraint",
            isExcluded(ipName(mappedCidr24), ipName(bytes(new int[]{ 192, 0, 2, 5 }))));

        // Out-of-range mapped SAN must NOT be caught (normalization isn't over-matching).
        isTrue("a mapped SAN outside the /24 must not be caught",
            !isExcluded(ipName(ipv4Cidr24), ipName(ipv4Mapped(198, 51, 100, 5))));

        // A mapped-address constraint with a mask narrower than /96 (here /64) is a genuine IPv6 range
        // and must NOT be collapsed to IPv4, so an IPv4 SAN must not match it.
        byte[] mappedNarrowMask = bytes(new int[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 0,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0 });
        isTrue("an IPv6-range constraint (mask < /96) must not be collapsed to match an IPv4 SAN",
            !isExcluded(ipName(mappedNarrowMask), ipName(bytes(new int[]{ 192, 0, 2, 5 }))));
    }

    /**
     * GSMA SGP.22 v2.5 relaxed directoryName name-constraint matching (github #2327): gated behind
     * {@link Properties#X509_SGP22_NAME_CONSTRAINTS}, off by default. With the flag set, additional
     * subject attributes are tolerated and serialNumber is matched with a startsWith comparison
     * wherever it appears; with the flag clear the strict RFC 5280 matching is unchanged.
     */
    private void testSGP22NameConstraints()
    {
        GeneralName subtreeExtra = directoryName("O=VALID, serialNumber=89034011");
        GeneralName subjectExtra = directoryName("C=ES, O=VALID, CN=VALID EUICC CD, OU=VALID, serialNumber=89034011026140000000000000001332");

        GeneralName subtreeSnFirst = directoryName("serialNumber=89034011, O=VALID");
        GeneralName subjectSnFirst = directoryName("serialNumber=89034011026140000000000000001332, O=VALID");

        // default (flag off): RFC 5280 strict prefix matching rejects both SGP.22 cases
        isTrue("SGP.22 extra-attributes should be rejected by default", !isPermitted(subtreeExtra, subjectExtra));
        isTrue("SGP.22 leading serialNumber should be rejected by default", !isPermitted(subtreeSnFirst, subjectSnFirst));

        System.setProperty(Properties.X509_SGP22_NAME_CONSTRAINTS, "true");
        try
        {
            // failure 1: subject carries extra attributes around the constrained O / serialNumber
            isTrue("SGP.22 extra-attributes should be permitted when enabled", isPermitted(subtreeExtra, subjectExtra));

            // failure 2: serialNumber is the leading RDN and must match via startsWith
            isTrue("SGP.22 leading serialNumber should be permitted when enabled", isPermitted(subtreeSnFirst, subjectSnFirst));

            // negative: a required organization that does not match is still rejected
            isTrue("mismatched organization must still be rejected",
                !isPermitted(subtreeExtra, directoryName("O=OTHER, serialNumber=89034011026140000000000000001332")));

            // negative: a serialNumber that is not a prefix is still rejected
            isTrue("non-prefix serialNumber must still be rejected",
                !isPermitted(subtreeExtra, directoryName("O=VALID, serialNumber=12340000000000000000000000000000")));

            // negative: a required attribute missing entirely is rejected
            isTrue("missing required serialNumber must be rejected",
                !isPermitted(subtreeExtra, directoryName("C=ES, O=VALID, CN=VALID EUICC CD")));
        }
        finally
        {
            System.getProperties().remove(Properties.X509_SGP22_NAME_CONSTRAINTS);
        }
    }

    /**
     * Regression test pinning the lone-serialNumber matching of a directoryName subtree. Before
     * github #2327 this GSMA SGP.22 startsWith concession ran ungated in the strict path; it is now
     * gated behind {@link Properties#X509_SGP22_NAME_CONSTRAINTS}, so default validation applies the
     * RFC 5280 sec. 7.1 equality comparison and the startsWith behaviour returns only with the flag.
     */
    private void testSGP22LegacySerialNumber()
    {
        GeneralName subtree = directoryName("serialNumber=89034011");
        GeneralName exact = directoryName("serialNumber=89034011");
        GeneralName prefix = directoryName("serialNumber=89034011026140000000000000001332");

        // default (flag off): RFC 5280 equality - an exact value matches, a longer value does not
        isTrue("exact serialNumber must match by default", isPermitted(subtree, exact));
        isTrue("prefix serialNumber must not match by default", !isPermitted(subtree, prefix));

        System.setProperty(Properties.X509_SGP22_NAME_CONSTRAINTS, "true");
        try
        {
            // flag on: the legacy GSMA SGP.22 startsWith comparison applies again
            isTrue("exact serialNumber must match when enabled", isPermitted(subtree, exact));
            isTrue("prefix serialNumber must match when enabled", isPermitted(subtree, prefix));
        }
        finally
        {
            System.getProperties().remove(Properties.X509_SGP22_NAME_CONSTRAINTS);
        }
    }

    private static GeneralName directoryName(String name)
    {
        return new GeneralName(GeneralName.directoryName, new X500Name(name));
    }

    private static boolean isPermitted(GeneralName permitted, GeneralName subject)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(new GeneralSubtree(permitted));
        try
        {
            validator.checkPermitted(subject);
            return true;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return false;
        }
    }

    private static boolean isExcluded(GeneralName excluded, GeneralName name)
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.addExcludedSubtree(new GeneralSubtree(excluded));
        try
        {
            validator.checkExcluded(name);
            return false;
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            return true;
        }
    }

    private static GeneralName uriName(String uri)
    {
        return new GeneralName(GeneralName.uniformResourceIdentifier, uri);
    }

    private static GeneralName dnsName(String dns)
    {
        return new GeneralName(GeneralName.dNSName, dns);
    }

    private static GeneralName emailName(String email)
    {
        return new GeneralName(GeneralName.rfc822Name, email);
    }

    private static GeneralName ipName(byte[] ip)
    {
        return new GeneralName(GeneralName.iPAddress, new DEROctetString(ip));
    }

    // ::ffff:a.b.c.d - a 16-byte IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2).
    private static byte[] ipv4Mapped(int a, int b, int c, int d)
    {
        return bytes(new int[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d });
    }

    private static byte[] bytes(int[] values)
    {
        byte[] result = new byte[values.length];
        for (int i = 0; i < values.length; i++)
        {
            result[i] = (byte)values[i];
        }
        return result;
    }

    /**
     * Tests string based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        String testName,
        String[] testNameIsConstraint,
        String[] testNameIsNotConstraint,
        String[] testNames1,
        String[] testNames2,
        String[][] testUnion,
        String[] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNameIsConstraint[i])));
            constraintValidator.checkPermitted(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNameIsNotConstraint[i])));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType, testName));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsConstraint[i])));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType, testName));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsNotConstraint[i])));
            constraintValidator.checkExcluded(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames1[i])));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames2[i])));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testUnion[i][j])));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNames1[i])));
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNames2[i])));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testInterSection[i])));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    /**
     * Tests byte array based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        byte[] testName,
        byte[][] testNameIsConstraint,
        byte[][] testNameIsNotConstraint,
        byte[][] testNames1,
        byte[][] testNames2,
        byte[][][] testUnion,
        byte[][] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsConstraint[i]))));
            constraintValidator.checkPermitted(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsNotConstraint[i]))));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsConstraint[i]))));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsNotConstraint[i]))));
            constraintValidator.checkExcluded(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames2[i]))));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DEROctetString(
                        testUnion[i][j]))));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames2[i]))));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testInterSection[i]))));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }

            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new PKIXNameConstraintsTest());
    }
}

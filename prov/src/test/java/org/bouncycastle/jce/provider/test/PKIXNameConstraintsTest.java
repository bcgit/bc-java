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

        testURIAuthorityParsing();
        testIPv4MappedIPv6Bypass();
        testTrailingDotDNSBypass();
    }

    /**
     * Regression test for possible IPv4-mapped IPv6 Name-Constraint bypass. Per RFC 4291
     * sec. 2.5.5.2, the IPv6 address {@code ::ffff:a.b.c.d} represents the
     * same host as the IPv4 address {@code a.b.c.d}. The PKIXNameConstraint
     * validator's {@code isIPConstrained} pre-filter compares
     * {@code ip.length == constraint.length / 2}, which is 16 vs 4 for a
     * 16-byte IPv4-mapped SAN against an 8-byte IPv4 (4-byte IP + 4-byte
     * mask) constraint, so the comparison short-circuits to "not
     * constrained" and the cert escapes the exclusion. The fix
     * normalises 16-byte {@code ::ffff:*} SANs (and 32-byte constraints
     * with the matching mask prefix) to their 4-byte / 8-byte forms
     * before the length check.
     */
    private void testIPv4MappedIPv6Bypass()
        throws Exception
    {
        // Excluded: IPv4 192.0.2.0/24 (8 bytes: IP || mask).
        byte[] excludedIPv4 = new byte[]{
            (byte)192, (byte)0, (byte)2, (byte)0,
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00
        };
        // SAN: ::ffff:192.0.2.1 (16-byte IPv4-mapped IPv6 form of 192.0.2.1).
        byte[] sanIPv4MappedIPv6 = new byte[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff,
            (byte)192, (byte)0, (byte)2, (byte)1
        };

        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.addExcludedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.iPAddress, new DEROctetString(excludedIPv4))));

        GeneralName san = new GeneralName(GeneralName.iPAddress, new DEROctetString(sanIPv4MappedIPv6));
        try
        {
            validator.checkExcluded(san);
            fail("IPv4-mapped IPv6 SAN must not escape an IPv4 excluded subtree "
                + "(F1 bypass; ::ffff:192.0.2.1 is 192.0.2.1 per RFC 4291 sec. 2.5.5.2)");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
            // The fix correctly recognises the IPv4-mapped IPv6 SAN as
            // being in the IPv4 192.0.2.0/24 excluded range.
        }

        // Symmetric case: permitted subtree is an IPv4 range, SAN encoded
        // as IPv4-mapped IPv6 of an IP outside that range must be rejected
        // (not silently permitted via length-mismatch fall-through).
        PKIXNameConstraintValidator permittedValidator = new PKIXNameConstraintValidator();
        permittedValidator.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.iPAddress, new DEROctetString(excludedIPv4))));

        byte[] sanIPv4MappedOutside = new byte[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff,
            (byte)203, (byte)0, (byte)113, (byte)1   // 203.0.113.1, outside 192.0.2.0/24
        };
        try
        {
            permittedValidator.checkPermitted(new GeneralName(
                GeneralName.iPAddress, new DEROctetString(sanIPv4MappedOutside)));
            fail("IPv4-mapped IPv6 SAN outside permitted IPv4 subtree must be rejected");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
        }

        // Positive case: in-range IPv4-mapped IPv6 must verify against an
        // IPv4 permitted subtree. Catches the over-correction where the
        // normalisation rejects all 16-byte SANs.
        byte[] sanIPv4MappedInside = new byte[]{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte)0xff, (byte)0xff,
            (byte)192, (byte)0, (byte)2, (byte)42    // 192.0.2.42, inside the subtree
        };
        permittedValidator.checkPermitted(new GeneralName(
            GeneralName.iPAddress, new DEROctetString(sanIPv4MappedInside)));
    }

    /**
     * Regression test for possible trailing-dot DNS Name-Constraint bypass.
     * A SAN dNSName like {@code "foo.example.com."} (trailing dot — the
     * RFC 1034 root label, legal IA5String per RFC 5280 sec. 4.2.1.6)
     * tokenises to {@code ["foo", "example", "com", ""]}. The four-label
     * test array against a two-label constraint {@code "example.com"}
     * miscounts in {@code withinDomain} so the constraint's
     * {@code "example"} aligns with the test's {@code "com"}, the
     * per-label compare returns false, and {@code isDNSConstrained}
     * declares the SAN "not constrained" — bypassing the exclusion. The
     * fix strips at most one trailing dot from both sides before the
     * label split.
     */
    private void testTrailingDotDNSBypass()
        throws Exception
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.addExcludedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.dNSName, "example.com")));

        try
        {
            validator.checkExcluded(new GeneralName(GeneralName.dNSName, "foo.example.com."));
            fail("Trailing-dot dNSName 'foo.example.com.' must not escape "
                + "the 'example.com' excluded subtree (F2 bypass)");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
        }

        // Exact-equality case (testing that the trailing-dot normalisation
        // also covers the dns.equalsIgnoreCase(constraint) path, not just
        // withinDomain).
        PKIXNameConstraintValidator exactValidator = new PKIXNameConstraintValidator();
        exactValidator.addExcludedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.dNSName, "evil.com")));
        try
        {
            exactValidator.checkExcluded(new GeneralName(GeneralName.dNSName, "evil.com."));
            fail("Trailing-dot dNSName 'evil.com.' must not escape the "
                + "'evil.com' excluded subtree via the exact-equality path");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
        }

        // Symmetric: a legitimate trailing-dot SAN under a permitted
        // subtree must verify (no false-negative regression). Without
        // trailing-dot normalisation the permitted check incorrectly
        // rejects 'foo.example.com.' from a permitted 'example.com'.
        PKIXNameConstraintValidator permittedValidator = new PKIXNameConstraintValidator();
        permittedValidator.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.dNSName, "example.com")));
        permittedValidator.checkPermitted(new GeneralName(GeneralName.dNSName, "foo.example.com."));
    }

    /**
     * Regression test for possible URI authority-parsing bug in
     * {@code extractHostFromURL}. RFC 3986 §3.2 says the userinfo / host
     * boundary is the LAST '@' inside the authority, and the host / port
     * boundary is the LAST ':' AFTER the userinfo strip (or, for an IPv6
     * literal, the ':' AFTER the closing ']'). Previously
     * {@code extractHostFromURL} stripped the port first via
     * {@code lastIndexOf(':')} on the full authority — which, for a URI
     * with userinfo but no explicit port (e.g. {@code https://attacker:foo@victim.com/}),
     * found the userinfo's colon and returned {@code "attacker"} as the
     * "host". A Name-Constrained intermediate CA could then mint a cert
     * with SAN URI {@code https://<permitted>:x@<attacker>/} that would
     * pass a constraint check on {@code <permitted>} while the real
     * authority was {@code <attacker>}. IPv6 bracketed-literal authority
     * forms (with or without userinfo, with or without port) were also
     * mishandled because the inner colons confused both the port and
     * userinfo splits.
     */
    private void testURIAuthorityParsing()
        throws Exception
    {
        PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
        validator.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.uniformResourceIdentifier, "victim.com")));

        // Userinfo "attacker:foo@" with permitted-host "victim.com": the
        // real authority is victim.com; pre-fix code returned "attacker"
        // and rejected with a false-negative diagnostic. With the fix the
        // host extracts to "victim.com" and the URI is correctly accepted.
        validator.checkPermitted(new GeneralName(GeneralName.uniformResourceIdentifier,
            "https://attacker:foo@victim.com/path"));

        // The exploit-bearing case: permitted = "attacker.com", SAN URI =
        // "https://attacker.com:x@victim.com/". Pre-fix BC extracted
        // "attacker.com" (wrong — the real host is victim.com) and
        // accepted the cert. Post-fix BC extracts "victim.com" and
        // correctly rejects.
        PKIXNameConstraintValidator forgery = new PKIXNameConstraintValidator();
        forgery.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.uniformResourceIdentifier, "attacker.com")));
        try
        {
            forgery.checkPermitted(new GeneralName(GeneralName.uniformResourceIdentifier,
                "https://attacker.com:x@victim.com/"));
            fail("forged userinfo URI must not satisfy a permitted-subtree check on the userinfo host");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
            // expected
        }

        // Bracketed IPv6 literal with port; pre-fix code returned junk
        // (":1]") because the IPv6 inner ':' tripped the userinfo split.
        // Post-fix the literal extracts cleanly so e.g. an excluded
        // "[::1]" subtree (if it existed) would match — for this test we
        // assert the simpler property that a permitted "victim.com" does
        // not accept a "[::1]:443" URI.
        PKIXNameConstraintValidator ipv6Test = new PKIXNameConstraintValidator();
        ipv6Test.intersectPermittedSubtree(new GeneralSubtree(
            new GeneralName(GeneralName.uniformResourceIdentifier, "victim.com")));
        try
        {
            ipv6Test.checkPermitted(new GeneralName(GeneralName.uniformResourceIdentifier,
                "https://[::1]:443/"));
            fail("IPv6 literal must not satisfy a permitted DNS-form URI subtree");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
            // expected
        }

        // Bracketed IPv6 with userinfo and port: the inner ':' colons plus
        // the userinfo '@' all combined to derail pre-fix parsing.
        try
        {
            ipv6Test.checkPermitted(new GeneralName(GeneralName.uniformResourceIdentifier,
                "https://user:pass@[::1]:443/"));
            fail("IPv6+userinfo+port URI must not satisfy a permitted DNS-form subtree");
        }
        catch (PKIXNameConstraintValidatorException expected)
        {
            // expected
        }
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

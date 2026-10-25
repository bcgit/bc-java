package org.bouncycastle.jce.provider.test;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.ldap.LDAPUtils;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Check LDAPUtils.parseDN only takes an attribute as the type of an RDN component (github #2511).
 */
public class LDAPUtilsTest
    extends SimpleTest
{
    public String getName()
    {
        return "LDAPUtils";
    }

    public void performTest()
        throws Exception
    {
        // the attribute name must not match inside another attribute's value
        checkParse("CN=Bob Root CA, OU=Trust Services, O=Example, C=DE", "o", "Example");
        checkParse("O=Acn Corp,CN=Alice", "cn", "Alice");
        checkParse("CN=Root, C=DE", "c", "DE");
        checkParse("OU=Trust Services, O=Example", "ou", "Trust Services");
        checkParse("O=cn=x, CN=Alice", "cn", "Alice");

        // empty values, or a value ending in the attribute name, used to throw
        checkParse("O=cn,L=y", "cn", "");
        checkParse("O=x,CN=", "cn", "");
        checkParse("O=x, CN= ", "cn", "");
        checkParse("CN=\"\"", "cn", "");

        // absent attribute
        checkParse("CN=Alice, O=Example", "ou", "");
        checkParse("", "cn", "");

        // case insensitive, first occurrence
        checkParse("cn=Alice,CN=Bob", "CN", "Alice");

        // escaped and quoted separators stay in the value, '+' ends a multi-valued RDN component
        checkParse("CN=Smith\\, John, O=Example", "cn", "Smith, John");
        checkParse("CN=a\\\\,O=Example", "o", "Example");
        checkParse("CN=\"Smith, John\", O=Example", "cn", "Smith, John");
        checkParse("CN=Bob+UID=bob, O=Example", "cn", "Bob");
        checkParse("CN=Bob+UID=bob, O=Example", "uid", "bob");

        // the RFC 1779 form from X500Principal.getName("RFC1779") quotes a value holding a separator, so
        // an "o=" inside one must not be taken, and spaces the '+' of a multi-valued RDN
        checkParse("CN=\"x, o=y\", O=Example", "o", "Example");
        checkParse("CN=Bob + OID.0.9.2342.19200300.100.1.1=bob, O=Example", "cn", "Bob");
        checkParse("CN=\"Bob \", O=Example", "cn", "Bob ");
        checkParse("CN=Bob\\ ,O=Example", "cn", "Bob ");

        // the escapes of the string form are decoded, so the value is searched for as it is stored
        checkParse("CN=\"say \\\"hi\\\"\", O=Example", "cn", "say \"hi\"");
        checkParse("CN=\"back\\\\slash\", O=Example", "cn", "back\\5cslash");
        checkParse("CN=caf\\C3\\A9, O=Example", "cn", "caf\u00e9");
        checkParse("CN=\\23hash\\2C x, O=Example", "cn", "#hash, x");
        checkParse("CN=\\ lead, O=Example", "cn", " lead");
        checkParse("CN=bad\\FF, O=Example", "cn", "bad\u00ff");
        checkParse("CN=a\\\\ + O=b", "cn", "a\\5c");
        checkParse("CN=abc\\\",O=b", "cn", "abc\"");
        checkParse("CN=#0403616263 , O=Example", "cn", "#0403616263");

        // the decoding agrees with X500Principal
        checkPrincipal("CN=Smith\\, John,O=Example", "Smith, John");
        checkPrincipal("CN=say \\\"hi\\\",O=Example", "say \"hi\"");
        checkPrincipal("CN=back\\\\slash,O=Example", "back\\5cslash");
        checkPrincipal("CN=Bob\\ ,O=Example", "Bob ");

        // the value is still escaped for use in a filter (CVE-2023-33201)
        checkParse("CN=chars[*()\\\\\0], O=Example", "cn", "chars[\\2a\\28\\29\\5c\\00]");
        checkParse("CN=nul\\00, O=Example", "cn", "nul\\00");
    }

    private void checkParse(String dn, String attributeName, String expected)
    {
        String result = LDAPUtils.parseDN(dn, attributeName);

        isEquals("parse of " + attributeName + " from \"" + dn + "\" gave \"" + result + "\"", expected, result);
    }

    private void checkPrincipal(String dn, String expected)
    {
        X500Principal principal = new X500Principal(dn);

        checkParse(principal.getName(), "cn", expected);
        checkParse(principal.getName("RFC1779"), "cn", expected);
    }

    public static void main(String[] args)
    {
        runTest(new LDAPUtilsTest());
    }
}

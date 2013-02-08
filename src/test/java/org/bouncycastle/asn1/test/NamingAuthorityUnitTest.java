package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.x500.DirectoryString;

import java.io.IOException;

public class NamingAuthorityUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "NamingAuthority";
    }

    public void performTest()
        throws Exception
    {
        DERObjectIdentifier namingAuthorityID = new DERObjectIdentifier("1.2.3");
        String              namingAuthorityURL = "url";
        DirectoryString     namingAuthorityText = new DirectoryString("text");

        NamingAuthority auth =  new NamingAuthority(namingAuthorityID, namingAuthorityURL, namingAuthorityText);

        checkConstruction(auth, namingAuthorityID, namingAuthorityURL, namingAuthorityText);

        auth =  new NamingAuthority(null, namingAuthorityURL, namingAuthorityText);

        checkConstruction(auth, null, namingAuthorityURL, namingAuthorityText);

        auth =  new NamingAuthority(namingAuthorityID, null, namingAuthorityText);

        checkConstruction(auth, namingAuthorityID, null, namingAuthorityText);

        auth =  new NamingAuthority(namingAuthorityID, namingAuthorityURL, null);

        checkConstruction(auth, namingAuthorityID, namingAuthorityURL, null);

        auth = NamingAuthority.getInstance(null);

        if (auth != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            NamingAuthority.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        NamingAuthority auth,
        DERObjectIdentifier namingAuthorityID,
        String              namingAuthorityURL,
        DirectoryString     namingAuthorityText)
        throws IOException
    {
        checkValues(auth, namingAuthorityID, namingAuthorityURL, namingAuthorityText);

        auth = NamingAuthority.getInstance(auth);

        checkValues(auth, namingAuthorityID, namingAuthorityURL, namingAuthorityText);

        ASN1InputStream aIn = new ASN1InputStream(auth.toASN1Object().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        auth = NamingAuthority.getInstance(seq);

        checkValues(auth, namingAuthorityID, namingAuthorityURL, namingAuthorityText);
    }

    private void checkValues(
        NamingAuthority auth,
        DERObjectIdentifier namingAuthorityId,
        String              namingAuthorityURL,
        DirectoryString     namingAuthorityText)
    {
        checkOptionalField("namingAuthorityId", namingAuthorityId, auth.getNamingAuthorityId());
        checkOptionalField("namingAuthorityURL", namingAuthorityURL, auth.getNamingAuthorityUrl());
        checkOptionalField("namingAuthorityText", namingAuthorityText, auth.getNamingAuthorityText());
    }

    public static void main(
        String[]    args)
    {
        runTest(new NamingAuthorityUnitTest());
    }
}

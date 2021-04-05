package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
import org.bouncycastle.asn1.isismtt.x509.ProcurationSyntax;
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
import org.bouncycastle.asn1.x500.DirectoryString;

public class ProfessionInfoUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "ProfessionInfo";
    }

    public void performTest()
        throws Exception
    {
        NamingAuthority auth =  new NamingAuthority(new ASN1ObjectIdentifier("1.2.3"), "url", new DirectoryString("fred"));
        DirectoryString[] professionItems = { new DirectoryString("substitution") };
        ASN1ObjectIdentifier[] professionOids = { new ASN1ObjectIdentifier("1.2.3") };
        String registrationNumber = "12345";
        DEROctetString addProfInfo = new DEROctetString(new byte[20]);

        ProfessionInfo info = new ProfessionInfo(auth, professionItems, professionOids, registrationNumber, addProfInfo);

        checkConstruction(info, auth, professionItems, professionOids, registrationNumber, addProfInfo);

        info = new ProfessionInfo(null, professionItems, professionOids, registrationNumber, addProfInfo);

        checkConstruction(info, null, professionItems, professionOids, registrationNumber, addProfInfo);

        info = new ProfessionInfo(auth, professionItems, null, registrationNumber, addProfInfo);

        checkConstruction(info, auth, professionItems, null, registrationNumber, addProfInfo);

        info = new ProfessionInfo(auth, professionItems, professionOids, null, addProfInfo);

        checkConstruction(info, auth, professionItems, professionOids, null, addProfInfo);

        info = new ProfessionInfo(auth, professionItems, professionOids, registrationNumber, null);

        checkConstruction(info, auth, professionItems, professionOids, registrationNumber, null);

        info = ProfessionInfo.getInstance(null);

        if (info != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            ProcurationSyntax.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        ProfessionInfo profInfo,
        NamingAuthority auth,
        DirectoryString[] professionItems,
        ASN1ObjectIdentifier[] professionOids,
        String registrationNumber,
        DEROctetString addProfInfo)
        throws IOException
    {
        checkValues(profInfo, auth, professionItems, professionOids, registrationNumber, addProfInfo);

        profInfo = ProfessionInfo.getInstance(profInfo);

        checkValues(profInfo, auth, professionItems, professionOids, registrationNumber, addProfInfo);

        ASN1InputStream aIn = new ASN1InputStream(profInfo.toASN1Primitive().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        profInfo = ProfessionInfo.getInstance(seq);

        checkValues(profInfo, auth, professionItems, professionOids, registrationNumber, addProfInfo);
    }

    private void checkValues(
        ProfessionInfo profInfo,
        NamingAuthority auth,
        DirectoryString[] professionItems,
        ASN1ObjectIdentifier[] professionOids,
        String registrationNumber,
        DEROctetString addProfInfo)
    {
        checkOptionalField("auth", auth, profInfo.getNamingAuthority());
        checkMandatoryField("professionItems", professionItems[0], profInfo.getProfessionItems()[0]);
        if (professionOids != null)
        {
            checkOptionalField("professionOids", professionOids[0], profInfo.getProfessionOIDs()[0]);
        }
        checkOptionalField("registrationNumber", registrationNumber, profInfo.getRegistrationNumber());
        checkOptionalField("addProfessionInfo", addProfInfo, profInfo.getAddProfessionInfo());
    }

    public static void main(
        String[]    args)
    {
        runTest(new ProfessionInfoUnitTest());
    }
}

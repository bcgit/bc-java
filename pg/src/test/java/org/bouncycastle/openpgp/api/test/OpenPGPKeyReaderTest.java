package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;

public class OpenPGPKeyReaderTest
        extends APITest
{
    @Override
    public String getName()
    {
        return "OpenPGPKeyReaderTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws PGPException, IOException
    {
        testParseEmptyCollection(api);
        testParse2CertsCertificateCollection(api);
        testParseCertAndKeyToCertificateCollection(api);
    }

    private void testParseEmptyCollection(OpenPGPApi api)
            throws IOException
    {
        byte[] empty = new byte[0];
        List<OpenPGPCertificate> certs = api.readKeyOrCertificate().parseKeysOrCertificates(empty);
        isTrue(certs.isEmpty());
    }

    private void testParse2CertsCertificateCollection(OpenPGPApi api)
            throws IOException
    {
        OpenPGPCertificate alice = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT);
        OpenPGPCertificate bob = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.BOB_CERT);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder().clearHeaders().build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        alice.getPGPPublicKeyRing().encode(pOut);
        bob.getPGPPublicKeyRing().encode(pOut);
        pOut.close();
        aOut.close();

        List<OpenPGPCertificate> certs = api.readKeyOrCertificate().parseKeysOrCertificates(bOut.toByteArray());
        isEquals("Collection MUST contain both items", 2, certs.size());

        isEquals(alice.getKeyIdentifier(), certs.get(0).getKeyIdentifier());
        isEquals(bob.getKeyIdentifier(), certs.get(1).getKeyIdentifier());
    }

    private void testParseCertAndKeyToCertificateCollection(OpenPGPApi api)
            throws IOException
    {
        OpenPGPCertificate alice = api.readKeyOrCertificate().parseCertificate(OpenPGPTestKeys.ALICE_CERT);
        OpenPGPKey bob = api.readKeyOrCertificate().parseKey(OpenPGPTestKeys.BOB_KEY);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder().clearHeaders().build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        alice.getPGPPublicKeyRing().encode(pOut);
        bob.getPGPSecretKeyRing().encode(pOut);
        pOut.close();
        aOut.close();

        List<OpenPGPCertificate> certs = api.readKeyOrCertificate().parseKeysOrCertificates(bOut.toByteArray());
        isEquals("Collection MUST contain both items", 2, certs.size());

        isEquals(alice.getKeyIdentifier(), certs.get(0).getKeyIdentifier());
        isFalse(certs.get(0).isSecretKey());

        isEquals(bob.getKeyIdentifier(), certs.get(1).getKeyIdentifier());
        isTrue(certs.get(1).isSecretKey());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPKeyReaderTest());
    }
}

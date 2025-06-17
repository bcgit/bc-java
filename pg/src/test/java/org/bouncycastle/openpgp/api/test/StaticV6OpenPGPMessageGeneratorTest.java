package org.bouncycastle.openpgp.api.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.openpgp.OpenPGPTestKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;
import org.bouncycastle.openpgp.api.OpenPGPMessageGenerator;
import org.bouncycastle.openpgp.api.OpenPGPMessageOutputStream;
import org.bouncycastle.openpgp.api.OpenPGPPolicy;
import org.bouncycastle.openpgp.api.SubkeySelector;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class StaticV6OpenPGPMessageGeneratorTest
        extends AbstractPacketTest
{
    private final OpenPGPKeyReader reader = new OpenPGPKeyReader();

    KeyIdentifier signingKeyIdentifier = new KeyIdentifier(
            Hex.decode("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"));
    KeyIdentifier encryptionKeyIdentifier = new KeyIdentifier(
            Hex.decode("12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885"));

    @Override
    public String getName()
    {
        return "StaticV6OpenPGPMessageGeneratorTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        staticEncryptedMessage();
        staticSignedMessage();
    }

    private void staticEncryptedMessage()
            throws IOException, PGPException
    {
        OpenPGPKey key = reader.parseKey(OpenPGPTestKeys.V6_KEY);

        OpenPGPMessageGenerator gen = getStaticGenerator()
                .addEncryptionCertificate(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream pgOut = (OpenPGPMessageOutputStream) gen.open(bOut);
        pgOut.write(Strings.toUTF8ByteArray("Hello, World!\n"));
        pgOut.close();

        System.out.println(bOut);
    }

    private void staticSignedMessage()
            throws IOException, PGPException
    {
        OpenPGPKey key = reader.parseKey(OpenPGPTestKeys.V6_KEY);
        OpenPGPMessageGenerator gen = getStaticGenerator()
                .addSigningKey(key);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OpenPGPMessageOutputStream pgOut = (OpenPGPMessageOutputStream) gen.open(bOut);
        pgOut.write(Strings.toUTF8ByteArray("Hello, World!\n"));
        pgOut.close();

        System.out.println(bOut);
    }

    /**
     * Return a pre-configured {@link OpenPGPMessageGenerator} which has the complex logic of evaluating
     * recipient keys to determine suitable subkeys, algorithms etc. swapped out for static configuration
     * tailored to the V6 test key.
     *
     * @return static message generator
     */
    public OpenPGPMessageGenerator getStaticGenerator()
    {
        OpenPGPMessageGenerator gen = new OpenPGPMessageGenerator()
                .setSigningKeySelector(new SubkeySelector()
                {
                    public List<OpenPGPCertificate.OpenPGPComponentKey> select(
                            OpenPGPCertificate certificate, OpenPGPPolicy policy)
                    {
                        return Collections.singletonList(certificate.getKey(signingKeyIdentifier));
                    }
                })
                .setEncryptionKeySelector(
                        new SubkeySelector() {
                            public List<OpenPGPCertificate.OpenPGPComponentKey> select(OpenPGPCertificate certificate, OpenPGPPolicy policy) {
                                return Collections.singletonList(certificate.getKey(encryptionKeyIdentifier));
                            }
                        });

        return gen;
    }

    public static void main(String[] args)
    {
        runTest(new StaticV6OpenPGPMessageGeneratorTest());
    }
}

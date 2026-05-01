package org.bouncycastle.openpgp.api.test;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.api.KeyPairGeneratorCallback;
import org.bouncycastle.openpgp.api.OpenPGPApi;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.SignatureParameters;
import org.bouncycastle.openpgp.api.SignatureSubpacketsFunction;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;

public class OpenPGPV4KeyGenerationTest
        extends APITest
{
    @Override
    public String getName()
    {
        return "OpenPGPV4KeyGenerationTest";
    }

    @Override
    protected void performTestWith(OpenPGPApi api)
            throws PGPException
    {
        generateRSAKey(api);
    }

    private void generateRSAKey(OpenPGPApi api)
            throws PGPException
    {
        OpenPGPKey key = api.generateKey(PublicKeyPacket.VERSION_4)
                .withPrimaryKey(new KeyPairGeneratorCallback()
                {
                    @Override
                    public PGPKeyPair generateFrom(PGPKeyPairGenerator generator)
                            throws PGPException
                    {
                        return generator.generateRsaKeyPair(3072);
                    }
                }, SignatureParameters.Callback.Util.modifyHashedSubpackets(new SignatureSubpacketsFunction()
                {
                    @Override
                    public PGPSignatureSubpacketGenerator apply(PGPSignatureSubpacketGenerator subpackets)
                    {
                        subpackets.removePacketsOfType(SignatureSubpacketTags.KEY_FLAGS);
                        subpackets.setKeyFlags(KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA | KeyFlags.ENCRYPT_STORAGE | KeyFlags.ENCRYPT_COMMS);
                        return subpackets;
                    }
                }))
                .addUserId("Alice <alice@example.org>")
                .build();

        isEquals(PublicKeyPacket.VERSION_4, key.getPrimaryKey().getVersion());
    }

    public static void main(String[] args)
    {
        runTest(new OpenPGPV4KeyGenerationTest());
    }
}

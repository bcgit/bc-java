package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.test.AbstractPacketTest;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;

import java.security.KeyPair;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public abstract class AbstractPgpKeyPairTest
        extends AbstractPacketTest
{

    public static Date parseUTCTimestamp(String timestamp)
    {
        // Not thread safe, so we use a local variable
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        try
        {
            return dateFormat.parse(timestamp);
        }
        catch (ParseException e)
        {
            throw new RuntimeException(e);
        }
    }

    public Date currentTimeRounded()
    {
        Date now = new Date();
        return new Date((now.getTime() / 1000) * 1000); // rounded to seconds
    }

    public BcPGPKeyPair toBcKeyPair(JcaPGPKeyPair keyPair)
            throws PGPException
    {
        BcPGPKeyConverter c = new BcPGPKeyConverter();
        return new BcPGPKeyPair(keyPair.getPublicKey().getVersion(), keyPair.getPublicKey().getAlgorithm(),
                new AsymmetricCipherKeyPair(
                        c.getPublicKey(keyPair.getPublicKey()),
                        c.getPrivateKey(keyPair.getPrivateKey())),
                keyPair.getPublicKey().getCreationTime());
    }

    public JcaPGPKeyPair toJcaKeyPair(BcPGPKeyPair keyPair)
            throws PGPException
    {
        JcaPGPKeyConverter c = new JcaPGPKeyConverter().setProvider(new BouncyCastleProvider());
        return new JcaPGPKeyPair(keyPair.getPublicKey().getVersion(), keyPair.getPublicKey().getAlgorithm(),
                new KeyPair(
                        c.getPublicKey(keyPair.getPublicKey()),
                        c.getPrivateKey(keyPair.getPrivateKey())),
                keyPair.getPublicKey().getCreationTime());
    }
}

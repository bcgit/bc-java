package org.bouncycastle.crypto.tls;

import java.math.BigInteger;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.util.Strings;

/**
 * An implementation of {@link TlsSRPIdentityManager} that simulates the existence of "unknown" identities
 * to obscure the fact that there is no verifier for them. 
 */
public class SimulatedTlsSRPIdentityManager
    implements TlsSRPIdentityManager
{
    private static final byte[] PREFIX_PASSWORD = Strings.toByteArray("password");
    private static final byte[] PREFIX_SALT = Strings.toByteArray("salt");

    /**
     * Create a {@link SimulatedTlsSRPIdentityManager} that implements the algorithm from RFC 5054 2.5.1.3
     *
     * @param group the {@link SRP6GroupParameters} defining the group that SRP is operating in
     * @param seedKey the secret "seed key" referred to in RFC 5054 2.5.1.3
     * @return an instance of {@link SimulatedTlsSRPIdentityManager}
     */
    public static SimulatedTlsSRPIdentityManager getRFC5054Default(SRP6GroupParameters group, byte[] seedKey)
    {
        SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
        verifierGenerator.init(group, TlsUtils.createHash(HashAlgorithm.sha1));

        HMac mac = new HMac(TlsUtils.createHash(HashAlgorithm.sha1));
        mac.init(new KeyParameter(seedKey));

        return new SimulatedTlsSRPIdentityManager(group, verifierGenerator, mac);
    }

    protected SRP6GroupParameters group;
    protected SRP6VerifierGenerator verifierGenerator;
    protected Mac mac;

    public SimulatedTlsSRPIdentityManager(SRP6GroupParameters group, SRP6VerifierGenerator verifierGenerator, Mac mac)
    {
        this.group = group;
        this.verifierGenerator = verifierGenerator;
        this.mac = mac;
    }

    public TlsSRPLoginParameters getLoginParameters(byte[] identity)
    {
        mac.update(PREFIX_SALT, 0, PREFIX_SALT.length);
        mac.update(identity, 0, identity.length);

        byte[] salt = new byte[mac.getMacSize()];
        mac.doFinal(salt, 0);

        mac.update(PREFIX_PASSWORD, 0, PREFIX_PASSWORD.length);
        mac.update(identity, 0, identity.length);

        byte[] password = new byte[mac.getMacSize()];
        mac.doFinal(password, 0);

        BigInteger verifier = verifierGenerator.generateVerifier(salt, identity, password);

        return new TlsSRPLoginParameters(group, verifier, salt);
    }
}

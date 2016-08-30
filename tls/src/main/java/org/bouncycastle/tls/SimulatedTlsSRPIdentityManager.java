package org.bouncycastle.tls;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.SRP6GroupParameters;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsSRPConfig;
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
    public static SimulatedTlsSRPIdentityManager getRFC5054Default(TlsCrypto crypto, SRP6GroupParameters group, byte[] seedKey)
        throws IOException
    {
        SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
        verifierGenerator.init(group, new SHA1Digest());

        TlsHMAC mac = crypto.createHMAC(MACAlgorithm.hmac_sha1);

        mac.setKey(seedKey);

        return new SimulatedTlsSRPIdentityManager(group, verifierGenerator, mac);
    }

    protected SRP6GroupParameters group;
    protected SRP6VerifierGenerator verifierGenerator;
    protected TlsHMAC mac;

    public SimulatedTlsSRPIdentityManager(SRP6GroupParameters group, SRP6VerifierGenerator verifierGenerator, TlsHMAC mac)
    {
        this.group = group;
        this.verifierGenerator = verifierGenerator;
        this.mac = mac;
    }

    public TlsSRPLoginParameters getLoginParameters(byte[] identity)
    {
        mac.update(PREFIX_SALT, 0, PREFIX_SALT.length);
        mac.update(identity, 0, identity.length);

        byte[] salt = mac.calculateMAC();

        mac.update(PREFIX_PASSWORD, 0, PREFIX_PASSWORD.length);
        mac.update(identity, 0, identity.length);

        byte[] password = mac.calculateMAC();

        BigInteger verifier = verifierGenerator.generateVerifier(salt, identity, password);

        TlsSRPConfig srpConfig = new TlsSRPConfig();
        srpConfig.setExplicitNG(new BigInteger[]{ group.getN(), group.getG() });

        return new TlsSRPLoginParameters(srpConfig, verifier, salt);
    }
}

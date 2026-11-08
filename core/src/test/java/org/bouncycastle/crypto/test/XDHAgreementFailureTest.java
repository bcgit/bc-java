package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * An X25519 / X448 agreement with a low-order peer key yields the all-zero secret and is refused. The caller's output
 * buffer must be left as it was, so a caller that mishandles the exception does not end up holding an all-zero
 * "shared secret" that anyone can predict.
 */
public class XDHAgreementFailureTest
    extends SimpleTest
{
    private static final SecureRandom random = new SecureRandom();

    private static final byte FILL = (byte)0xAA;

    public String getName()
    {
        return "XDHAgreementFailure";
    }

    public void performTest()
        throws Exception
    {
        // X25519: a low-order peer leaves the buffer, at an offset, unchanged
        X25519Agreement x25519 = new X25519Agreement();
        x25519.init(new X25519PrivateKeyParameters(random));
        byte[] buf = filled(x25519.getAgreementSize() + 7);
        try
        {
            x25519.calculateAgreement(new X25519PublicKeyParameters(new byte[X25519PublicKeyParameters.KEY_SIZE]), buf, 7);
            fail("X25519 low-order peer accepted");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        isTrue("X25519 buffer changed by a failed agreement", Arrays.areEqual(filled(buf.length), buf));

        // X448 likewise
        X448Agreement x448 = new X448Agreement();
        x448.init(new X448PrivateKeyParameters(random));
        buf = filled(x448.getAgreementSize() + 7);
        try
        {
            x448.calculateAgreement(new X448PublicKeyParameters(new byte[X448PublicKeyParameters.KEY_SIZE]), buf, 7);
            fail("X448 low-order peer accepted");
        }
        catch (IllegalStateException e)
        {
            // expected
        }
        isTrue("X448 buffer changed by a failed agreement", Arrays.areEqual(filled(buf.length), buf));

        // a normal agreement still produces matching, non-zero secrets at an offset
        X25519PrivateKeyParameters a = new X25519PrivateKeyParameters(random);
        X25519PrivateKeyParameters b = new X25519PrivateKeyParameters(random);
        byte[] sa = new byte[X25519PrivateKeyParameters.SECRET_SIZE + 3];
        byte[] sb = new byte[X25519PrivateKeyParameters.SECRET_SIZE];
        a.generateSecret(b.generatePublicKey(), sa, 3);
        b.generateSecret(a.generatePublicKey(), sb, 0);
        isTrue("X25519 secrets differ", Arrays.areEqual(sb, Arrays.copyOfRange(sa, 3, sa.length)));
        isTrue("X25519 secret all zero", !Arrays.areAllZeroes(sb, 0, sb.length));

        X448PrivateKeyParameters c = new X448PrivateKeyParameters(random);
        X448PrivateKeyParameters d = new X448PrivateKeyParameters(random);
        byte[] sc = new byte[X448PrivateKeyParameters.SECRET_SIZE + 3];
        byte[] sd = new byte[X448PrivateKeyParameters.SECRET_SIZE];
        c.generateSecret(d.generatePublicKey(), sc, 3);
        d.generateSecret(c.generatePublicKey(), sd, 0);
        isTrue("X448 secrets differ", Arrays.areEqual(sd, Arrays.copyOfRange(sc, 3, sc.length)));
        isTrue("X448 secret all zero", !Arrays.areAllZeroes(sd, 0, sd.length));
    }

    private static byte[] filled(int length)
    {
        byte[] buf = new byte[length];
        Arrays.fill(buf, FILL);
        return buf;
    }

    public static void main(String[] args)
    {
        runTest(new XDHAgreementFailureTest());
    }
}

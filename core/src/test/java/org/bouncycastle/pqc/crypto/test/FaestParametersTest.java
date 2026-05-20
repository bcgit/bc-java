package org.bouncycastle.pqc.crypto.test;

import org.bouncycastle.pqc.crypto.faest.FaestParameters;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Sanity-check the FaestParameters constants. Values are cross-checked
 * against the spec-derived calculations in
 * {@code faest-ref/instances.c} (CALC_K / CALC_TAU0 / CALC_TAU1 / CALC_L)
 * and against the upstream {@code build/parameters.h} per-paramset macros.
 */
public class FaestParametersTest
    extends SimpleTest
{
    public String getName()
    {
        return "FaestParameters";
    }

    public void performTest()
        throws Exception
    {
        FaestParameters[] all = {
            FaestParameters.faest_128s, FaestParameters.faest_128f,
            FaestParameters.faest_192s, FaestParameters.faest_192f,
            FaestParameters.faest_256s, FaestParameters.faest_256f,
            FaestParameters.faest_em_128s, FaestParameters.faest_em_128f,
            FaestParameters.faest_em_192s, FaestParameters.faest_em_192f,
            FaestParameters.faest_em_256s, FaestParameters.faest_em_256f
        };

        // Twelve parameter sets per spec v2.0.
        isEquals("parameter-set count", 12, all.length);

        for (int i = 0; i != all.length; i++)
        {
            FaestParameters p = all[i];

            // byName round-trips.
            isTrue("byName(" + p.getName() + ")", p == FaestParameters.byName(p.getName()));

            // Each ELL is divisible by 8 (witness packed in bytes).
            isTrue(p.getName() + ": ell % 8 == 0", (p.getEll() & 7) == 0);

            // lambda ∈ {128, 192, 256}.
            isTrue(p.getName() + ": lambda in {128,192,256}",
                p.getLambda() == 128 || p.getLambda() == 192 || p.getLambda() == 256);

            // lambdaBytes = lambda / 8.
            isEquals(p.getName() + ": lambdaBytes", p.getLambda() / 8, p.getLambdaBytes());

            // Derived: tau == tau0 + tau1.
            isEquals(p.getName() + ": tau == tau0+tau1", p.getTau(), p.getTau0() + p.getTau1());

            // Derived: k = ((lambda - wGrind) / tau) + 1.
            int expectedK = ((p.getLambda() - p.getWGrind()) / p.getTau()) + 1;
            isEquals(p.getName() + ": k formula", expectedK, p.getK());

            // Derived: tau1 = (lambda - wGrind) % tau.
            int expectedTau1 = (p.getLambda() - p.getWGrind()) % p.getTau();
            isEquals(p.getName() + ": tau1 formula", expectedTau1, p.getTau1());

            // Derived: L = tau1 * 2^k + tau0 * 2^(k-1).
            int expectedL = p.getTau1() * (1 << p.getK()) + p.getTau0() * (1 << (p.getK() - 1));
            isEquals(p.getName() + ": L formula", expectedL, p.getL());

            // EM variants must have Ske == 0 per faest_param.c (no key schedule
            // for the Even-Mansour construction).
            if (p.isEm())
            {
                isEquals(p.getName() + ": EM Ske==0", 0, p.getSke());
            }

            // Public/secret key sizes match the spec table.
            isTrue(p.getName() + ": pkSize > 0", p.getPkSize() > 0);
            isTrue(p.getName() + ": skSize > 0", p.getSkSize() > 0);
            isTrue(p.getName() + ": sigSize > 0", p.getSigSize() > 0);
        }

        // Spot-check three specific values against parameters.h to catch any
        // future typo in the FaestParameters constants.
        isEquals("faest_128s SIG_SIZE",        4506, FaestParameters.faest_128s.getSigSize());
        isEquals("faest_256f SIG_SIZE",       26548, FaestParameters.faest_256f.getSigSize());
        isEquals("faest_em_192s SIG_SIZE",     9340, FaestParameters.faest_em_192s.getSigSize());

        // faest_128s: lambda=128, tau=11, wGrind=7
        // tau1 = (128-7) % 11 = 0, tau0 = 11, k = (121/11)+1 = 12, L = 11 * 2^11
        isEquals("faest_128s k",    12, FaestParameters.faest_128s.getK());
        isEquals("faest_128s tau1",  0, FaestParameters.faest_128s.getTau1());
        isEquals("faest_128s tau0", 11, FaestParameters.faest_128s.getTau0());
        isEquals("faest_128s L",    11 * (1 << 11), FaestParameters.faest_128s.getL());

        // byName rejects unknown.
        isTrue("byName(unknown) == null", null == FaestParameters.byName("nope"));
    }

    public static void main(String[] args)
    {
        runTest(new FaestParametersTest());
    }
}

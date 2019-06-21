package org.bouncycastle.math.ec.endo;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.PreCompInfo;

public abstract class EndoUtil
{
    public static final String PRECOMP_NAME = "bc_endo";

    public static ECPoint mapPoint(final ECEndomorphism endomorphism, final ECPoint p)
    {
        final ECCurve c = p.getCurve();

        EndoPreCompInfo precomp = (EndoPreCompInfo)c.precompute(p, PRECOMP_NAME, new PreCompCallback()
        {
            public PreCompInfo precompute(PreCompInfo existing)
            {
                EndoPreCompInfo existingEndo = (existing instanceof EndoPreCompInfo) ? (EndoPreCompInfo)existing : null;

                if (checkExisting(existingEndo, endomorphism))
                {
                    return existingEndo;
                }

                ECPoint mappedPoint = endomorphism.getPointMap().map(p);

                EndoPreCompInfo result = new EndoPreCompInfo();
                result.setEndomorphism(endomorphism);
                result.setMappedPoint(mappedPoint);
                return result;
            }

            private boolean checkExisting(EndoPreCompInfo existingEndo, ECEndomorphism endomorphism)
            {
                return null != existingEndo
                    && existingEndo.getEndomorphism() == endomorphism
                    && existingEndo.getMappedPoint() != null;
            }
        });

        return precomp.getMappedPoint();
    }
}

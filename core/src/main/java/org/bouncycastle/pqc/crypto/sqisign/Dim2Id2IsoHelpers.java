package org.bouncycastle.pqc.crypto.sqisign;


import java.security.SecureRandom;

/**
 * Level-independent helpers from {@code src/id2iso/ref/lvlx/dim2id2iso.c}:
 * {@code post_LLL_basis_treatment}, {@code enumerate_hypercube},
 * {@code find_uv_from_lists}, the {@code compare_vec_by_norm} sort, and
 * {@code find_uv} itself.
 *
 * <p>The first four operate purely on {@link Ibz} structures. {@code find_uv}
 * takes the level-specific {@code ALTERNATE_CONNECTING_IDEALS} precomp array
 * as a parameter; level-specific drivers (e.g.
 * {@link Dim2Id2IsoLvl1}) wire in
 * the lvl1 table once it has been transcribed.</p>
 */
final class Dim2Id2IsoHelpers
{
    private Dim2Id2IsoHelpers()
    {
    }

    /**
     * {@code post_LLL_basis_treatment}: reorder LLL output and flip signs so
     * the basis is in a "nice" canonical form when {@code isSpecialOrder} is
     * true. When {@code isSpecialOrder} is false this is a no-op.
     *
     * <p>Mutates both {@code gram} and {@code reduced} in place. The
     * {@code norm} parameter is unused in the C body and is kept on the API
     * surface only to mirror the C signature for future-proofing — callers
     * may pass {@code null}.</p>
     *
     * @param gram            4x4 Gram matrix of the reduced basis (mutated).
     * @param reduced         4x4 basis whose columns are the reduced vectors
     *                        (mutated; columns may be permuted and/or negated).
     * @param isSpecialOrder  true iff the left order is the standard
     *                        extremal one; only then is any treatment applied.
     */
    public static void postLLLBasisTreatment(Ibz[][] gram, Ibz[][] reduced,
                                             boolean isSpecialOrder)
    {
        if (!isSpecialOrder)
        {
            return;
        }

        // Reorder the basis if the gram matrix has a repeated diagonal entry
        // matching gram[0][0]. The three cases swap a pair of basis columns
        // and the corresponding gram rows / columns.
        if (Ibz.cmp(gram[0][0], gram[2][2]) == 0)
        {
            // Swap columns 1 and 2 of `reduced`.
            for (int i = 0; i < 4; i++)
            {
                Ibz.swap(reduced[i][1], reduced[i][2]);
            }
            Ibz.swap(gram[0][2], gram[0][1]);
            Ibz.swap(gram[2][0], gram[1][0]);
            Ibz.swap(gram[3][2], gram[3][1]);
            Ibz.swap(gram[2][3], gram[1][3]);
            Ibz.swap(gram[2][2], gram[1][1]);
        }
        else if (Ibz.cmp(gram[0][0], gram[3][3]) == 0)
        {
            // Swap columns 1 and 3 of `reduced`.
            for (int i = 0; i < 4; i++)
            {
                Ibz.swap(reduced[i][1], reduced[i][3]);
            }
            Ibz.swap(gram[0][3], gram[0][1]);
            Ibz.swap(gram[3][0], gram[1][0]);
            Ibz.swap(gram[2][3], gram[2][1]);
            Ibz.swap(gram[3][2], gram[1][2]);
            Ibz.swap(gram[3][3], gram[1][1]);
        }
        else if (Ibz.cmp(gram[1][1], gram[3][3]) == 0)
        {
            // Same as the first case (swap columns 1 and 2). Mirrors the
            // verbatim repetition in the C reference.
            for (int i = 0; i < 4; i++)
            {
                Ibz.swap(reduced[i][1], reduced[i][2]);
            }
            Ibz.swap(gram[0][2], gram[0][1]);
            Ibz.swap(gram[2][0], gram[1][0]);
            Ibz.swap(gram[3][2], gram[3][1]);
            Ibz.swap(gram[2][3], gram[1][3]);
            Ibz.swap(gram[2][2], gram[1][1]);
        }

        // Sign adjustments: ensure reduced[0][0] == reduced[1][1] and
        // reduced[0][2] == reduced[1][3]. Flip the offending column (and
        // matching gram row/column) when they disagree.
        if (Ibz.cmp(reduced[0][0], reduced[1][1]) != 0)
        {
            for (int i = 0; i < 4; i++)
            {
                Ibz.neg(reduced[i][1], reduced[i][1]);
                Ibz.neg(gram[i][1], gram[i][1]);
                Ibz.neg(gram[1][i], gram[1][i]);
            }
        }
        if (Ibz.cmp(reduced[0][2], reduced[1][3]) != 0)
        {
            for (int i = 0; i < 4; i++)
            {
                Ibz.neg(reduced[i][3], reduced[i][3]);
                Ibz.neg(gram[i][3], gram[i][3]);
                Ibz.neg(gram[3][i], gram[3][i]);
            }
        }
    }

    /**
     * Allocate a fresh {@code [count][4]} array of initialized {@link Ibz}
     * entries — convenience for callers of
     * {@link #enumerateHypercube(Ibz[][], Ibz[], int, Ibz[][], Ibz)}.
     */
    public static Ibz[][] allocVecs(int count)
    {
        Ibz[][] out = new Ibz[count][4];
        for (int i = 0; i < count; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                out[i][j] = new Ibz();
            }
        }
        return out;
    }

    /**
     * Allocate a fresh array of {@code count} initialized {@link Ibz}
     * entries — convenience for callers of
     * {@link #enumerateHypercube(Ibz[][], Ibz[], int, Ibz[][], Ibz)}.
     */
    public static Ibz[] allocNorms(int count)
    {
        Ibz[] out = new Ibz[count];
        for (int i = 0; i < count; i++)
        {
            out[i] = new Ibz();
        }
        return out;
    }

    /**
     * {@code enumerate_hypercube}: enumerate all vectors in an infinity-norm
     * hypercube of radius {@code m} (i.e. coordinates in {@code [-m, m]}),
     * filtered by symmetry and divisibility, with odd quotient norm.
     *
     * <p>For each surviving vector {@code v = (x,y,z,w)} the squared-norm
     * {@code v^T · gram · v} is divided by {@code adjustedNorm}; only vectors
     * whose quotient is an integer (the C reference {@code assert}s) and is
     * odd are written into {@code vecs} / {@code norms} (the quotient).</p>
     *
     * <p>The caller must pre-allocate {@code vecs} and {@code norms} to hold
     * at least the worst-case number of vectors. A safe upper bound is
     * {@code (2m+1)^4}; convenience allocators are
     * {@link #allocVecs(int)} and {@link #allocNorms(int)}.</p>
     *
     * @return {@code count - 1}, where {@code count} is the number of vectors
     *         written. This mirrors the C return convention exactly — callers
     *         use the returned value as the exclusive upper bound in their
     *         {@code for (i = 0; i < returnedValue; ++i)} loop, so the last
     *         vector written is intentionally not consumed.
     */
    public static int enumerateHypercube(Ibz[][] vecs, Ibz[] norms, int m,
                                         Ibz[][] gram, Ibz adjustedNorm)
    {
        if (m <= 0)
        {
            throw new IllegalArgumentException("m must be positive");
        }

        Ibz remain = new Ibz();
        Ibz norm = new Ibz();
        Ibz[] point = new Ibz[]{new Ibz(), new Ibz(), new Ibz(), new Ibz()};

        int count = 0;
        int dim = 2 * m + 1;
        int dim2 = dim * dim;
        int dim3 = dim2 * dim;

        // If the basis is of the form { alpha, i*alpha, beta, i*beta }, we
        // can quotient by the order-4 rotation acting on (x,y,z,w).
        boolean needRemoveSymmetry =
            Ibz.cmp(gram[0][0], gram[1][1]) == 0
            && Ibz.cmp(gram[3][3], gram[2][2]) == 0;

        // Enumerate (x, y, z, w) over the hypercube, breaking ±-symmetry with
        // a lexicographic non-positive cut: only the lex-min representative
        // of each antipodal pair is visited.
        for (int x = -m; x <= 0; x++)                  // non-positive x
        {
            for (int y = -m; y <= m; y++)
            {
                if (x == 0 && y > 0)
                {
                    break;
                }
                for (int z = -m; z <= m; z++)
                {
                    if (x == 0 && y == 0 && z > 0)
                    {
                        break;
                    }
                    for (int w = -m; w <= m; w++)
                    {
                        if (x == 0 && y == 0 && z == 0 && w >= 0)
                        {
                            break;
                        }

                        // Drop vectors with all coords even — they
                        // represent a vector scaled by 2.
                        if (((x | y | z | w) & 1) == 0)
                        {
                            continue;
                        }
                        // Drop vectors with all coords divisible by 3.
                        if (x % 3 == 0 && y % 3 == 0 && z % 3 == 0 && w % 3 == 0)
                        {
                            continue;
                        }

                        int check1 = (m + w) + dim * (m + z)
                            + dim2 * (m + y) + dim3 * (m + x);
                        int check2 = (m - z) + dim * (m + w)
                            + dim2 * (m - x) + dim3 * (m + y);
                        int check3 = (m + z) + dim * (m - w)
                            + dim2 * (m + x) + dim3 * (m - y);

                        // Either there is no symmetry, or we keep only the
                        // lex-min representative of each rotation orbit.
                        if (needRemoveSymmetry
                            && !(check1 <= check2 && check1 <= check3))
                        {
                            continue;
                        }

                        Ibz.set(point[0], x);
                        Ibz.set(point[1], y);
                        Ibz.set(point[2], z);
                        Ibz.set(point[3], w);

                        IbzMat.qfEval(norm, gram, point);
                        Ibz.div(norm, remain, norm, adjustedNorm);
                        if (Ibz.isZero(remain) == 0)
                        {
                            // The C reference asserts this; in Java we
                            // surface it as IllegalStateException so the
                            // caller sees the failure rather than getting a
                            // bogus quotient.
                            throw new IllegalStateException(
                                "enumerate_hypercube: norm not divisible by adjusted_norm");
                        }

                        // Keep only vectors with odd quotient norm.
                        if (norm.v.testBit(0))
                        {
                            Ibz.set(vecs[count][0], x);
                            Ibz.set(vecs[count][1], y);
                            Ibz.set(vecs[count][2], z);
                            Ibz.set(vecs[count][3], w);
                            Ibz.copy(norms[count], norm);
                            count++;
                        }
                    }
                }
            }
        }

        // C returns count - 1; callers use it as an exclusive iteration
        // bound which intentionally skips the last-written entry.
        return count - 1;
    }

    /**
     * Stable sort over (vecs, norms) by ascending norm, mirroring
     * {@code compare_vec_by_norm} + {@code qsort} from
     * {@code src/id2iso/ref/lvlx/dim2id2iso.c}. The original C comparator ties
     * on norm-equal entries by their original index (the stable-sort
     * convention); the insertion sort below is stable — it shifts only on a
     * strict {@code >}, so norm-equal entries keep their original index order.
     *
     * <p>Sorts in place. Only the first {@code count} entries of each array
     * are touched; the rest are left as-is.</p>
     */
    public static void sortByNorm(Ibz[][] vecs, Ibz[] norms, int count)
    {
        if (count <= 1)
        {
            return;
        }
        int[] idx = new int[count];
        for (int i = 0; i < count; i++)
        {
            idx[i] = i;
        }
        // Stable insertion sort of idx by ascending norm; ties keep original order.
        for (int i = 1; i < count; i++)
        {
            int cur = idx[i];
            int j = i - 1;
            while (j >= 0 && Ibz.cmp(norms[idx[j]], norms[cur]) > 0)
            {
                idx[j + 1] = idx[j];
                j--;
            }
            idx[j + 1] = cur;
        }

        // Materialize the permutation back into vecs / norms.
        Ibz[][] vecsCopy = new Ibz[count][];
        Ibz[] normsCopy = new Ibz[count];
        for (int i = 0; i < count; i++)
        {
            vecsCopy[i] = vecs[i];
            normsCopy[i] = norms[i];
        }
        for (int i = 0; i < count; i++)
        {
            vecs[i] = vecsCopy[idx[i]];
            norms[i] = normsCopy[idx[i]];
        }
    }

    /**
     * {@code find_uv_from_lists} from
     * {@code src/id2iso/ref/lvlx/dim2id2iso.c}: search the two pre-enumerated
     * lists of small norms for a pair {@code (d1, d2) = (small_norms1[i1],
     * small_norms2[i2])} together with positive integers {@code u, v}
     * satisfying {@code u·d1 + v·d2 = target}.
     *
     * <p>The {@code numberSumSquare} switch controls how strict the search
     * is on {@code u, v}:</p>
     * <ul>
     *   <li>{@code 0} — accept any positive {@code (u, v)};</li>
     *   <li>{@code 1} — require {@code v} to factor as a sum of two squares
     *       (writes {@code av, bv} via Cornacchia);</li>
     *   <li>{@code 2} — require both {@code u} and {@code v} to factor as
     *       sums of two squares (writes both {@code (au, bu)} and
     *       {@code (av, bv)}).</li>
     * </ul>
     *
     * <p>On success returns 1 and writes the chosen indices to
     * {@code indexSol[0] = i1}, {@code indexSol[1] = i2}; on failure
     * returns 0 and leaves all outputs in an unspecified state.</p>
     *
     * @param au              Cornacchia output for {@code u} (only set when
     *                        {@code numberSumSquare == 2}).
     * @param bu              second Cornacchia output for {@code u}.
     * @param av              Cornacchia output for {@code v} (set when
     *                        {@code numberSumSquare >= 1}).
     * @param bv              second Cornacchia output for {@code v}.
     * @param u               output {@code u} satisfying {@code u·d1 + v·d2 = target}.
     * @param v               output {@code v} satisfying {@code u·d1 + v·d2 = target}.
     * @param indexSol        length-2 array: on return, [0] = i1, [1] = i2.
     * @param target          the target norm to split as {@code u·d1 + v·d2}.
     * @param smallNorms1     candidate d1 values (length {@code index1}).
     * @param smallNorms2     candidate d2 values (length {@code index2}).
     * @param quotients       precomputed {@code floor(target / smallNorms2[i])}.
     * @param index1          number of d1 candidates to consider.
     * @param index2          number of d2 candidates to consider.
     * @param isDiagonal      if true, restrict the second loop to {@code i2 >= i1}
     *                        (mirroring {@code is_diagonal}; used when the two
     *                        lists are the same).
     * @param numberSumSquare 0, 1, or 2 (see method-level javadoc).
     * @return 1 on success, 0 on failure.
     */
    public static int findUvFromLists(Ibz au, Ibz bu, Ibz av, Ibz bv,
                                      Ibz u, Ibz v,
                                      int[] indexSol,
                                      Ibz target,
                                      Ibz[] smallNorms1, Ibz[] smallNorms2,
                                      Ibz[] quotients,
                                      int index1, int index2,
                                      boolean isDiagonal,
                                      int numberSumSquare)
    {
        Ibz n = new Ibz();
        Ibz remain = new Ibz();
        Ibz adjustedNorm = new Ibz();
        Ibz.copy(n, target);

        int found = 0;

        outer:
        for (int i1 = 0; i1 < index1; i1++)
        {
            // adjusted_norm = n mod small_norms1[i1]
            Ibz.mod(adjustedNorm, n, smallNorms1[i1]);
            int startingIndex2 = isDiagonal ? i1 : 0;

            for (int i2 = startingIndex2; i2 < index2; i2++)
            {
                // v = (target / d1) mod d2  via  v = adjustedNorm * d2^{-1} mod d1
                if (Ibz.invmod(remain, smallNorms2[i2], smallNorms1[i1]) == 0)
                {
                    continue;
                }
                Ibz.mul(v, remain, adjustedNorm);
                Ibz.mod(v, v, smallNorms1[i1]);

                int cmp = Ibz.cmp(v, quotients[i2]);
                while (found == 0 && cmp < 0)
                {
                    if (numberSumSquare > 0)
                    {
                        found = Cornacchia.cornacchiaPrime(av, bv, Ibz.ONE, v);
                    }
                    else
                    {
                        found = 1;
                    }
                    if (found == 1)
                    {
                        // u = (n - v*d2) / d1
                        Ibz.mul(remain, v, smallNorms2[i2]);
                        Ibz.copy(au, n);
                        Ibz.sub(u, au, remain);
                        if (u.v.signum() <= 0)
                        {
                            // u must be strictly positive (C asserts this).
                            // If the precondition is violated we treat the
                            // candidate as a rejection.
                            found = 0;
                        }
                        else
                        {
                            Ibz.div(u, remain, u, smallNorms1[i1]);
                            if (Ibz.isZero(remain) == 0)
                            {
                                // C asserts u·d1 + v·d2 == n exactly; if
                                // not, treat as rejection.
                                found = 0;
                            }
                        }

                        // Skip cases where u or v is a big power of two —
                        // mirrors the {@code ibz_get(u) != 0 && ibz_get(v) != 0}
                        // check, which throws out values whose low limb is
                        // zero (i.e., divisible by 2^WORD_SIZE).
                        if (found == 1)
                        {
                            int loU = Ibz.get(u);
                            int loV = Ibz.get(v);
                            if (loU == 0 || loV == 0)
                            {
                                found = 0;
                            }
                        }

                        if (found == 1 && numberSumSquare == 2)
                        {
                            found = Cornacchia.cornacchiaPrime(au, bu, Ibz.ONE, u);
                        }
                    }
                    if (found == 0)
                    {
                        Ibz.add(v, v, smallNorms1[i1]);
                        cmp = Ibz.cmp(v, quotients[i2]);
                    }
                }

                if (found == 1)
                {
                    indexSol[0] = i1;
                    indexSol[1] = i2;
                    break outer;
                }
            }
        }

        return found;
    }

    // ------------------------------------------------------------------
    // find_uv
    // ------------------------------------------------------------------

    /**
     * Result bundle for {@link #findUv}. Mirrors the C output-by-pointer
     * pattern as a single returned struct.
     */
    public static final class FindUvResult
    {
        public final Ibz u = new Ibz();
        public final Ibz v = new Ibz();
        public final QuatAlg.Elem beta1 = new QuatAlg.Elem();
        public final QuatAlg.Elem beta2 = new QuatAlg.Elem();
        public final Ibz d1 = new Ibz();
        public final Ibz d2 = new Ibz();
        public int indexAlternateOrder1;
        public int indexAlternateOrder2;
    }

    /**
     * Java port of {@code find_uv} from
     * {@code src/id2iso/ref/lvlx/dim2id2iso.c}. Searches across the standard
     * order O₀ (index 0) and the {@code numAlternateOrder} alternate
     * connecting ideals for a pair {@code (d1, d2)} with positive integers
     * {@code (u, v)} satisfying {@code u·d1 + v·d2 = target}, together with
     * the quaternion-algebra elements {@code beta1, beta2} that realise the
     * found norms.
     *
     * <p>The {@code alternateConnectingIdeals} parameter is the level-specific
     * precomp table — for lvl1 it has 6 entries (one per alternate extremal
     * order, 1-indexed in the C reference). When the precomp table has not
     * yet been transcribed callers can pass {@code null} together with
     * {@code numAlternateOrder == 0} to restrict the search to the standard
     * order alone.</p>
     *
     * @param target                 norm to split as {@code u·d1 + v·d2}.
     * @param lideal                 input left ideal (over the standard order).
     * @param alg                    quaternion algebra (typically QUATALG_PINFTY).
     * @param numAlternateOrder      number of alternate extremal orders to
     *                               include (lvl1: 6). Must be 0 when
     *                               {@code alternateConnectingIdeals} is null
     *                               or shorter.
     * @param alternateConnectingIdeals  level-specific precomp; entry [i]
     *                                   corresponds to the C reference's
     *                                   {@code ALTERNATE_CONNECTING_IDEALS[i]}
     *                                   (note: 0-indexed in Java, 0-indexed
     *                                   in C as well).
     * @param boxSize                FINDUV_box_size (lvl1: 2).
     * @param cubeSize               FINDUV_cube_size (lvl1: 624) — allocation
     *                               capacity for the per-order vec / norm
     *                               buffers.
     * @return a populated {@link FindUvResult} on success, or {@code null}
     *         if no candidate was found.
     */
    public static FindUvResult findUv(Ibz target,
                                      QuatLeftIdeal lideal,
                                      QuatAlg alg,
                                      int numAlternateOrder,
                                      QuatLeftIdeal[] alternateConnectingIdeals,
                                      int boxSize,
                                      int cubeSize)
    {
        if (numAlternateOrder < 0)
        {
            throw new IllegalArgumentException("numAlternateOrder must be >= 0");
        }
        if (numAlternateOrder > 0
            && (alternateConnectingIdeals == null
                || alternateConnectingIdeals.length < numAlternateOrder))
        {
            throw new IllegalArgumentException(
                "alternateConnectingIdeals shorter than numAlternateOrder");
        }

        int numOrders = numAlternateOrder + 1;
        Ibz n = new Ibz();
        Ibz.copy(n, target);
        Ibz remain = new Ibz();
        Ibz normD = new Ibz();

        // Per-order workspaces.
        Ibz[] adjustedNorm = new Ibz[numOrders];
        Ibz[][][] gram = new Ibz[numOrders][][];
        Ibz[][][] reduced = new Ibz[numOrders][][];
        QuatLeftIdeal[] ideal = new QuatLeftIdeal[numOrders];
        for (int i = 0; i < numOrders; i++)
        {
            adjustedNorm[i] = new Ibz();
            gram[i] = IbzMat.init4x4();
            reduced[i] = IbzMat.init4x4();
            ideal[i] = new QuatLeftIdeal();
        }

        // -- Set up ideal[0] = lideal, LLL-reduce, post-treat as "special". --
        QuatLeftIdeal.copy(ideal[0], lideal);
        LllApplications.reduceBasis(reduced[0], gram[0], ideal[0], alg);
        IbzMat.copy4x4(ideal[0].lattice.basis, reduced[0]);
        Ibz.set(adjustedNorm[0], 1);
        Ibz.mul(adjustedNorm[0], adjustedNorm[0], ideal[0].lattice.denom);
        Ibz.mul(adjustedNorm[0], adjustedNorm[0], ideal[0].lattice.denom);
        postLLLBasisTreatment(gram[0], reduced[0], true);

        // -- Replace ideal[0] by the equivalent ideal of smallest norm
        //    via delta · ideal[0], where delta is the first reduced-basis
        //    column (i.e. evaluating (1,0,0,0) through `reduced[0]`).        --
        QuatLeftIdeal reducedId = new QuatLeftIdeal();
        QuatLeftIdeal.copy(reducedId, ideal[0]);
        QuatAlg.Elem delta = new QuatAlg.Elem();
        Ibz.set(delta.coord[0], 1);
        Ibz.set(delta.coord[1], 0);
        Ibz.set(delta.coord[2], 0);
        Ibz.set(delta.coord[3], 0);
        Ibz.copy(delta.denom, reducedId.lattice.denom);
        Ibz[] tmpCoord = IbzVec.init4();
        IbzMat.eval4x4(tmpCoord, reduced[0], delta.coord);
        for (int t = 0; t < 4; t++)
        {
            Ibz.copy(delta.coord[t], tmpCoord[t]);
        }

        // reduced_id = ideal[0] · conj(delta) / n(ideal[0])
        QuatAlg.conj(delta, delta);
        Ibz.mul(delta.denom, delta.denom, ideal[0].norm);
        QuatLattice.algElemMul(reducedId.lattice, reducedId.lattice, delta, alg);
        Ibz.copy(reducedId.norm, gram[0][0][0]);
        Ibz.div(reducedId.norm, remain, reducedId.norm, adjustedNorm[0]);
        // The C asserts remain == 0 here; if not, we have garbage state.
        if (Ibz.isZero(remain) == 0)
        {
            return null;
        }

        // conj_ideal = conjugate of reduced_id.
        QuatLattice rightOrder = new QuatLattice();
        QuatLeftIdeal conjIdeal = new QuatLeftIdeal();
        QuatLeftIdeal.conjugateWithoutHnf(conjIdeal, rightOrder, reducedId, alg);

        // -- For each alternate connecting ideal, build ideal[i] = conj_ideal · ACI[i-1],
        //    LLL-reduce and post-treat as non-special.                       --
        for (int i = 1; i < numOrders; i++)
        {
            LllApplications.lidealMulReduced(
                ideal[i], gram[i], conjIdeal, alternateConnectingIdeals[i - 1], alg);
            IbzMat.copy4x4(reduced[i], ideal[i].lattice.basis);
            Ibz.set(adjustedNorm[i], 1);
            Ibz.mul(adjustedNorm[i], adjustedNorm[i], ideal[i].lattice.denom);
            Ibz.mul(adjustedNorm[i], adjustedNorm[i], ideal[i].lattice.denom);
            postLLLBasisTreatment(gram[i], reduced[i], false);
        }

        // -- Enumerate the hypercube for each order, sort by norm and
        //    precompute target / d2 quotients.                               --
        int m = boxSize;
        Ibz[][][] smallVecs = new Ibz[numOrders][][];
        Ibz[][] smallNorms = new Ibz[numOrders][];
        Ibz[][] quotients = new Ibz[numOrders][];
        int[] indices = new int[numOrders];
        for (int j = 0; j < numOrders; j++)
        {
            smallVecs[j] = allocVecs(cubeSize);
            smallNorms[j] = allocNorms(cubeSize);
            quotients[j] = allocNorms(cubeSize);

            int ret = enumerateHypercube(smallVecs[j], smallNorms[j], m,
                gram[j], adjustedNorm[j]);
            // The C reference returns count-1 and uses it directly as the
            // iteration bound — this intentionally skips the last-written
            // entry. Mirroring that behaviour is essential for KAT-identity.
            int count = Math.max(ret, 0);
            indices[j] = count;

            sortByNorm(smallVecs[j], smallNorms[j], count);
            for (int i = 0; i < count; i++)
            {
                Ibz.div(quotients[j][i], remain, n, smallNorms[j][i]);
            }
        }

        // -- Search for a (j1, j2) pair with a valid (d1, d2, u, v). --
        int found = 0;
        int i1 = -1;
        int i2 = -1;
        int foundJ1 = -1;
        int foundJ2 = -1;
        Ibz au = new Ibz(), bu = new Ibz();
        Ibz av = new Ibz(), bv = new Ibz();
        Ibz u = new Ibz(), v = new Ibz();
        int[] indexSol = new int[2];

        outer:
        for (int j1 = 0; j1 < numOrders; j1++)
        {
            for (int j2 = j1; j2 < numOrders; j2++)
            {
                boolean isDiago = (j1 == j2);
                indexSol[0] = -1;
                indexSol[1] = -1;
                found = findUvFromLists(
                    au, bu, av, bv, u, v, indexSol,
                    target, smallNorms[j1], smallNorms[j2], quotients[j2],
                    indices[j1], indices[j2], isDiago, 0);
                if (found == 1)
                {
                    i1 = indexSol[0];
                    i2 = indexSol[1];
                    foundJ1 = j1;
                    foundJ2 = j2;
                    break outer;
                }
            }
        }

        if (found == 0)
        {
            return null;
        }

        // -- Recover beta1, beta2, d1, d2 from the selected indices. --
        FindUvResult result = new FindUvResult();
        Ibz.copy(result.u, u);
        Ibz.copy(result.v, v);
        Ibz.copy(result.d1, smallNorms[foundJ1][i1]);
        Ibz.copy(result.d2, smallNorms[foundJ2][i2]);

        Ibz.copy(result.beta1.denom, ideal[foundJ1].lattice.denom);
        Ibz.copy(result.beta2.denom, ideal[foundJ2].lattice.denom);
        IbzMat.eval4x4(result.beta1.coord, reduced[foundJ1], smallVecs[foundJ1][i1]);
        IbzMat.eval4x4(result.beta2.coord, reduced[foundJ2], smallVecs[foundJ2][i2]);

        // -- For j > 0 entries, conjugate beta back to the original ideal
        //    via the algebra-element delta, then conjugate to land in the
        //    alternate order.                                               --
        if (foundJ1 != 0 || foundJ2 != 0)
        {
            // delta.denom /= lideal->norm; delta.denom *= conj_ideal.norm.
            Ibz.div(delta.denom, remain, delta.denom, lideal.norm);
            if (Ibz.isZero(remain) == 0)
            {
                return null;
            }
            Ibz.mul(delta.denom, delta.denom, conjIdeal.norm);
        }
        if (foundJ1 != 0)
        {
            QuatAlg.mul(result.beta1, delta, result.beta1, alg);
            QuatAlg.normalize(result.beta1);
            QuatAlg.conj(result.beta1, result.beta1);
        }
        if (foundJ2 != 0)
        {
            QuatAlg.mul(result.beta2, delta, result.beta2, alg);
            QuatAlg.normalize(result.beta2);
            QuatAlg.conj(result.beta2, result.beta2);
        }

        result.indexAlternateOrder1 = foundJ1;
        result.indexAlternateOrder2 = foundJ2;
        return result;
    }

    // ------------------------------------------------------------------
    // _fixed_degree_isogeny_impl
    // ------------------------------------------------------------------

    /**
     * Java port of {@code _fixed_degree_isogeny_impl} from
     * {@code src/id2iso/ref/lvlx/dim2id2iso.c}: build an isogeny of degree
     * {@code u} from a starting curve E₀ (with known endomorphism ring) via
     * the dimension-2 isogeny trick, returning the codomain curve
     * (encapsulated in {@code E34}) and the images of any input points
     * {@code P12}.
     *
     * <p>The C reference looks up the per-order precomp data via
     * {@code CURVES_WITH_ENDOMORPHISMS[index_alternate_order]} and
     * {@code EXTREMAL_ORDERS[index_alternate_order]}; this Java port takes
     * the data as explicit parameters so it is callable today, before the
     * full lvl1 precomp transcription lands.</p>
     *
     * <p>Pipeline (mirrors the C body 1:1):</p>
     * <ol>
     *   <li>Decide the chain length: when {@code small=false} use
     *       {@code TORSION_EVEN_POWER - HD_extra_torsion}; otherwise use
     *       {@code bitsize(p) + QUAT_repres_bound_input - bitsize(u)}.</li>
     *   <li>Call {@code representInteger} to find {@code theta ∈ O} with
     *       norm {@code u·(2^L - u)}.</li>
     *   <li>Build the ideal {@code O·theta + O·u} via {@code lideal_create}.</li>
     *   <li>Double the precomputed even-torsion basis down to length L+2.</li>
     *   <li>Multiply {@code theta} by {@code u^{-1} mod 2^{L+2}} and apply
     *       it to the basis via {@code endomorphism_application_even_basis}.</li>
     *   <li>Run the (2,2)-chain on {@code E×E} with that kernel.</li>
     * </ol>
     *
     * @param lideal              output: left ideal of {@code O} of norm {@code u}.
     * @param u                   target isogeny degree (odd).
     * @param small               see C reference; controls the chain length.
     * @param E34                 output: codomain elliptic-product pair.
     * @param P12                 input/output: points to be pushed through
     *                            the isogeny (length {@code numP}; entries
     *                            are mutated in place).
     * @param numP                number of points in {@code P12}.
     * @param curveE              starting curve E (precomp:
     *                            {@code CURVES_WITH_ENDOMORPHISMS[idx].curve}).
     * @param basisEven           precomputed 2^TORSION_EVEN_POWER-torsion
     *                            basis on E (precomp:
     *                            {@code CURVES_WITH_ENDOMORPHISMS[idx].basis_even}).
     * @param riParams            quaternion-representation params for
     *                            {@code EXTREMAL_ORDERS[idx]}; used by
     *                            {@code representInteger}.
     * @param actionGen2          2x2 action matrix for the order's 2nd generator.
     * @param actionGen3          2x2 action matrix for the order's 3rd generator.
     * @param actionGen4          2x2 action matrix for the order's 4th generator.
     * @param alg                 quaternion algebra (typically QUATALG_PINFTY).
     * @param torsionEvenPower    {@code TORSION_EVEN_POWER} for the level.
     * @param hdExtraTorsion      {@code HD_extra_torsion} (2 for all levels).
     * @param quatRepresBoundInput  {@code QUAT_repres_bound_input}.
     * @param random              source of randomness for {@code representInteger}.
     * @return positive chain length {@code L} on success, 0 on failure.
     */
    public static int fixedDegreeIsogenyImpl(QuatLeftIdeal lideal, Ibz u, boolean small,
                                             ThetaCoupleCurve E34, ThetaCouplePoint[] P12, int numP,
                                             EcCurve curveE, EcBasis basisEven,
                                             QuatRepresentIntegerParams riParams,
                                             Ibz[][] actionGen2, Ibz[][] actionGen3,
                                             Ibz[][] actionGen4,
                                             QuatAlg alg,
                                             int torsionEvenPower, int hdExtraTorsion,
                                             int quatRepresBoundInput,
                                             SecureRandom random)
    {
        // Local mutable copy of E so we can normalize without touching the
        // caller's precomp.
        EcCurve E0 = new EcCurve();
        EcCurve.copy(E0, curveE);
        EcOps.normalizeCurveAndA24(E0);

        int uBitsize = Ibz.bitsize(u);
        int pBitsize = Ibz.bitsize(alg.p);

        // Choose chain length.
        int length;
        if (!small)
        {
            length = torsionEvenPower - hdExtraTorsion;
        }
        else
        {
            length = pBitsize + quatRepresBoundInput - uBitsize;
            if (uBitsize >= length || length >= torsionEvenPower - hdExtraTorsion)
            {
                return 0;
            }
        }
        if (length <= 0)
        {
            return 0;
        }

        // theta target norm = u · (2^L - u). Note u must be odd; the C
        // reference asserts this.
        if (!u.v.testBit(0))
        {
            return 0;
        }
        Ibz twoPow = new Ibz();
        Ibz tmp = new Ibz();
        Ibz.set(twoPow, 0);
        twoPow.v = java.math.BigInteger.ONE.shiftLeft(length);
        if (twoPow.v.compareTo(u.v) <= 0)
        {
            return 0;
        }
        Ibz.sub(tmp, twoPow, u);    // tmp = 2^L - u
        Ibz.mul(tmp, tmp, u);       // tmp = u · (2^L - u)
        if (!tmp.v.testBit(0))
        {
            return 0;
        }

        // representInteger: find theta in O of reduced-norm tmp.
        QuatAlg.Elem theta = new QuatAlg.Elem();
        int ret = Normeq.representInteger(theta, tmp, true, riParams, random);
        if (ret == 0)
        {
            return 0;
        }

        // Build lideal = O·theta + O·u.
        QuatLeftIdeal.create(lideal, theta, u, riParams.order.order, alg);

        // Double the even-torsion basis down to length + HD_extra_torsion.
        EcBasis B0Two = new EcBasis();
        EcBasis.copy(B0Two, basisEven);
        int dblCount = torsionEvenPower - length - hdExtraTorsion;
        if (dblCount > 0)
        {
            EcLadder.dblIterBasis(B0Two, dblCount, B0Two, E0);
        }

        // multiply theta by u^{-1} mod 2^{length+2}, in-place on theta.coord.
        java.math.BigInteger mod2Lp2 = java.math.BigInteger.ONE.shiftLeft(length + 2);
        java.math.BigInteger uInv;
        try
        {
            uInv = u.v.modInverse(mod2Lp2);
        }
        catch (ArithmeticException e)
        {
            // u is even mod 2^{length+2} — should have been caught above,
            // but be defensive.
            return 0;
        }
        Ibz uInvIbz = new Ibz(uInv);
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(theta.coord[i], theta.coord[i], uInvIbz);
        }

        // Apply theta to a copy of the (doubled) basis.
        EcBasis B0TwoTheta = new EcBasis();
        EcBasis.copy(B0TwoTheta, B0Two);
        int applied = Id2IsoHelpers.endomorphismApplicationEvenBasis(
            B0TwoTheta, E0, theta, length + hdExtraTorsion,
            riParams.order.order, actionGen2, actionGen3, actionGen4);
        if (applied != 1)
        {
            return 0;
        }

        // Build the (2,2)-isogeny chain on E×E with the gluing basis.
        ThetaCoupleCurve E00 = new ThetaCoupleCurve();
        EcCurve.copy(E00.E1, E0);
        EcCurve.copy(E00.E2, E0);

        ThetaKernelCouplePoints dimTwoKer = new ThetaKernelCouplePoints();
        HdOps.copyBasesToKernel(dimTwoKer, B0Two, B0TwoTheta);

        // Dispatch the (2,2)-isogeny chain to the level matching the curve's field.
        int chainRet;
        GfField fld = E0.field;
        if (fld == GfFieldLvl3.INSTANCE)
        {
            chainRet = ThetaChainLvl3.chainComputeAndEval(
                length, E00, dimTwoKer, true, E34, P12, numP);
        }
        else if (fld == GfFieldLvl5.INSTANCE)
        {
            chainRet = ThetaChainLvl5.chainComputeAndEval(
                length, E00, dimTwoKer, true, E34, P12, numP);
        }
        else
        {
            chainRet = ThetaChainLvl1.chainComputeAndEval(
                length, E00, dimTwoKer, true, E34, P12, numP);
        }
        if (chainRet == 0)
        {
            return 0;
        }

        return length;
    }

}

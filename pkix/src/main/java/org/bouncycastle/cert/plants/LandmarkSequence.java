package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.util.Exceptions;

/**
 * The published landmarks of a single issuance log, as defined by Section 6.4
 * of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>A landmark consists of a landmark number, the tree size at the time it
 * was allocated, and an expiration time in seconds since the POSIX Epoch
 * (Section 6.4.1). Landmarks are numbered consecutively from zero; landmark 0
 * has tree size 0 and expiry 0, tree sizes are strictly increasing and expiries
 * non-decreasing with the landmark number. A landmark that has not yet expired
 * is <em>active</em>; landmark 0 never is. Each landmark has two landmark
 * subtrees: the two subtrees of Section 4.5 that cover the entries added since
 * the previous landmark, or {@code [0, 0)} twice for landmark 0.</p>
 *
 * <p>A {@code LandmarkSequence} holds the window a CA publishes: the newest
 * landmark, {@code latest_landmark}, and the consecutive landmarks below it
 * down to at least one that has already expired. The published form
 * (Section 6.4.3) is plain text, each line terminated by U+000A:</p>
 * <pre>
 * &lt;latest_landmark&gt;
 * &lt;tree_size of landmark latest_landmark&gt; &lt;expiry of landmark latest_landmark&gt;
 * &lt;tree_size of landmark latest_landmark - 1&gt; &lt;expiry of landmark latest_landmark - 1&gt;
 * ...
 * </pre>
 * <p>Tree sizes are strictly decreasing and expiries non-increasing down the
 * document, and the document must reach an expired landmark so that the active
 * set is delimited. The draft-05 form, with a {@code num_active_landmarks}
 * count in the header and no expiry times, is no longer read or written.</p>
 */
public final class LandmarkSequence
{
    /** The largest landmark number or tree size the published form may carry, 2^48 - 1. */
    public static final long MAX_VALUE = 0xFFFFFFFFFFFFL;

    private final long latestLandmark;
    /** Tree sizes indexed by offset {@code i} from {@code latestLandmark}; index 0 is the largest. */
    private final long[] treeSizesNewestFirst;
    /** Expiry times, seconds since the Epoch, indexed as {@link #treeSizesNewestFirst}. */
    private final long[] expiriesNewestFirst;

    /**
     * @param latestLandmark       the landmark number of the newest landmark
     * @param treeSizesNewestFirst tree sizes for landmarks {@code latestLandmark}
     *                             down to {@code latestLandmark - n + 1}; strictly
     *                             decreasing
     * @param expiriesNewestFirst  expiry times, in seconds since the Epoch, for
     *                             the same landmarks in the same order; non-increasing
     */
    public LandmarkSequence(long latestLandmark, long[] treeSizesNewestFirst, long[] expiriesNewestFirst)
    {
        if (latestLandmark < 0 || latestLandmark > MAX_VALUE)
        {
            throw new IllegalArgumentException("latest_landmark out of range [0, 2^48-1]: " + latestLandmark);
        }
        int n = treeSizesNewestFirst.length;
        if (n < 1)
        {
            throw new IllegalArgumentException("at least one landmark required");
        }
        if (expiriesNewestFirst.length != n)
        {
            throw new IllegalArgumentException("one expiry time per tree size required");
        }
        if (n - 1 > latestLandmark)
        {
            throw new IllegalArgumentException(
                "more landmarks (" + n + ") than latest_landmark (" + latestLandmark + ") allows");
        }
        for (int i = 0; i < n; i++)
        {
            if (treeSizesNewestFirst[i] < 0 || treeSizesNewestFirst[i] > MAX_VALUE)
            {
                throw new IllegalArgumentException("tree size out of range [0, 2^48-1] at line " + (i + 2));
            }
            if (expiriesNewestFirst[i] < 0)
            {
                throw new IllegalArgumentException("negative expiry time at line " + (i + 2));
            }
            if (i > 0)
            {
                if (treeSizesNewestFirst[i] >= treeSizesNewestFirst[i - 1])
                {
                    throw new IllegalArgumentException(
                        "tree sizes must be strictly monotonically decreasing newest-first; "
                            + "violation at line " + (i + 2));
                }
                if (expiriesNewestFirst[i] > expiriesNewestFirst[i - 1])
                {
                    throw new IllegalArgumentException(
                        "expiration times must be monotonically decreasing newest-first; "
                            + "violation at line " + (i + 2));
                }
            }
        }
        // Landmark 0 has tree size 0 and expiry 0 (Section 6.4.1).
        if (latestLandmark - (n - 1) == 0 && (treeSizesNewestFirst[n - 1] != 0 || expiriesNewestFirst[n - 1] != 0))
        {
            throw new IllegalArgumentException("landmark 0 must have tree size 0 and expiry 0");
        }
        this.latestLandmark = latestLandmark;
        this.treeSizesNewestFirst = treeSizesNewestFirst.clone();
        this.expiriesNewestFirst = expiriesNewestFirst.clone();
    }

    /**
     * Parses a published landmark document (Section 6.4.3), requiring at least
     * one landmark to have expired as of the current time.
     *
     * @throws IOException if the document does not strictly conform
     */
    public static LandmarkSequence parse(String text)
        throws IOException
    {
        return parse(text, System.currentTimeMillis() / 1000L);
    }

    /**
     * Parses a published landmark document (Section 6.4.3). The document must
     * strictly conform: a header line holding {@code latest_landmark}, then one
     * line per landmark of {@code <tree_size> <expiry>}, every line terminated
     * by U+000A, no other whitespace, strictly decreasing tree sizes,
     * non-increasing expiry times, and at least one expiry before
     * {@code nowSeconds}.
     *
     * @param text       the document
     * @param nowSeconds the current time in seconds since the Epoch
     * @throws IOException if the document does not strictly conform
     */
    public static LandmarkSequence parse(String text, long nowSeconds)
        throws IOException
    {
        if (text.length() == 0 || text.charAt(text.length() - 1) != '\n')
        {
            throw new IOException("landmark document must end with a newline");
        }
        String[] lines = text.substring(0, text.length() - 1).split("\n", -1);
        if (lines.length < 2)
        {
            throw new IOException("landmark document must have at least 2 lines");
        }

        long latestLandmark = parseDecimal(lines[0], "latest_landmark", 1);
        if (latestLandmark > MAX_VALUE)
        {
            throw new IOException("latest_landmark exceeds 2^48-1: " + latestLandmark);
        }
        if (lines.length - 1 > latestLandmark + 1)
        {
            throw new IOException("more landmarks (" + (lines.length - 1) + ") than latest_landmark ("
                + latestLandmark + ") allows");
        }

        long[] treeSizes = new long[lines.length - 1];
        long[] expiries = new long[lines.length - 1];
        boolean expired = false;
        for (int i = 0; i < treeSizes.length; i++)
        {
            String line = lines[1 + i];
            int sp = line.indexOf(' ');
            if (sp < 0 || line.indexOf(' ', sp + 1) >= 0)
            {
                throw new IOException("line " + (2 + i) + " must be \"<tree_size> <expiry>\"");
            }
            treeSizes[i] = parseDecimal(line.substring(0, sp), "tree size", 2 + i);
            if (treeSizes[i] > MAX_VALUE)
            {
                throw new IOException("tree size on line " + (2 + i) + " exceeds 2^48-1");
            }
            expiries[i] = parseDecimal(line.substring(sp + 1), "expiry", 2 + i);
            if (expiries[i] < nowSeconds)
            {
                expired = true;
            }
        }
        if (!expired)
        {
            throw new IOException("landmark document contains no expired landmark");
        }

        try
        {
            return new LandmarkSequence(latestLandmark, treeSizes, expiries);
        }
        catch (IllegalArgumentException e)
        {
            // Re-wrap so callers see a single error type from parse failures.
            throw Exceptions.ioException(e.getMessage(), e);
        }
    }

    private static long parseDecimal(String s, String what, int lineNumber)
        throws IOException
    {
        if (s.length() == 0 || s.length() > 19)
        {
            throw new IOException(what + " on line " + lineNumber + " is not a decimal integer");
        }
        for (int i = 0; i < s.length(); i++)
        {
            char c = s.charAt(i);
            if (c < '0' || c > '9')
            {
                throw new IOException(what + " on line " + lineNumber + " is not a decimal integer");
            }
        }
        try
        {
            return Long.parseLong(s);
        }
        catch (NumberFormatException e)
        {
            throw Exceptions.ioException(what + " on line " + lineNumber + " is out of range", e);
        }
    }

    /**
     * Serializes the landmarks in the format defined by Section 6.4.3 (each
     * line terminated with U+000A).
     */
    public String format()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(latestLandmark).append('\n');
        for (int i = 0; i < treeSizesNewestFirst.length; i++)
        {
            sb.append(treeSizesNewestFirst[i]).append(' ').append(expiriesNewestFirst[i]).append('\n');
        }
        return sb.toString();
    }

    /** @return {@code latest_landmark}, the landmark number of the newest landmark. */
    public long getLastLandmark()
    {
        return latestLandmark;
    }

    /** @return the number of the oldest landmark this sequence holds. */
    public long getOldestLandmark()
    {
        return latestLandmark - (treeSizesNewestFirst.length - 1);
    }

    /**
     * @return the number of landmarks published beyond the terminating one, that
     *         is {@code num_active_landmarks} as of publication (Section 6.4.3)
     */
    public int getNumActiveLandmarks()
    {
        return treeSizesNewestFirst.length - 1;
    }

    /** @return the tree size of the landmark with the given number. */
    public long getTreeSize(long landmarkNumber)
    {
        return treeSizesNewestFirst[offset(landmarkNumber)];
    }

    /** @return the expiry time of the landmark with the given number, in seconds since the Epoch. */
    public long getExpiry(long landmarkNumber)
    {
        return expiriesNewestFirst[offset(landmarkNumber)];
    }

    /**
     * @return whether the landmark is active at {@code nowSeconds}, that is not
     *         yet expired (Section 6.4.1); landmark 0 is never active
     */
    public boolean isActive(long landmarkNumber, long nowSeconds)
    {
        return landmarkNumber > 0 && getExpiry(landmarkNumber) > nowSeconds;
    }

    private int offset(long landmarkNumber)
    {
        long offset = latestLandmark - landmarkNumber;
        if (offset < 0 || offset >= treeSizesNewestFirst.length)
        {
            throw new IndexOutOfBoundsException(
                "landmark " + landmarkNumber + " is outside the published window ["
                    + getOldestLandmark() + ", " + latestLandmark + "]");
        }
        return (int)offset;
    }

    /**
     * Returns the two landmark subtrees of a landmark (Section 6.4.1): the
     * subtrees of Section 4.5 covering the entries between the previous
     * landmark's tree size and this one's, or {@code [0, 0)} twice for
     * landmark 0. The previous landmark must be within the published window.
     *
     * @return the two subtrees as {@code {start, end}} pairs, left then right
     */
    public List<long[]> landmarkSubtrees(long landmarkNumber)
    {
        if (landmarkNumber == 0)
        {
            offset(0);
            List<long[]> zero = new ArrayList<long[]>(2);
            zero.add(new long[]{0, 0});
            zero.add(new long[]{0, 0});
            return Collections.unmodifiableList(zero);
        }
        long treeSize = getTreeSize(landmarkNumber);
        long prevTreeSize = getTreeSize(landmarkNumber - 1);
        return Collections.unmodifiableList(MerkleTreePrimitives.findCoveringSubtrees(prevTreeSize, treeSize));
    }

    /**
     * Returns the active landmark subtrees as of the current time, oldest
     * landmark first; see {@link #activeLandmarkSubtrees(long)}.
     */
    public List<long[]> activeLandmarkSubtrees()
    {
        return activeLandmarkSubtrees(System.currentTimeMillis() / 1000L);
    }

    /**
     * Returns the active landmark subtrees as of {@code nowSeconds}
     * (Section 6.4.1): the two landmark subtrees of every landmark in the
     * published window that has not yet expired and whose predecessor is also
     * in the window, ordered oldest landmark first. These are the subtrees a
     * relying party predistributes as trusted (Section 7.4).
     */
    public List<long[]> activeLandmarkSubtrees(long nowSeconds)
    {
        List<long[]> result = new ArrayList<long[]>();
        for (long landmark = getOldestLandmark() + 1; landmark <= latestLandmark; landmark++)
        {
            if (isActive(landmark, nowSeconds))
            {
                result.addAll(landmarkSubtrees(landmark));
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * Finds the landmark a landmark-relative certificate for entry
     * {@code index} is constructed against (Section 6.4.4 step 2): the lowest
     * numbered landmark whose tree size is greater than {@code index}.
     *
     * @return the landmark number, or {@code -1} if no published landmark
     *         contains the entry yet
     */
    public long landmarkFor(long index)
    {
        for (long landmark = getOldestLandmark(); landmark <= latestLandmark; landmark++)
        {
            if (getTreeSize(landmark) > index)
            {
                return landmark;
            }
        }
        return -1;
    }

    /**
     * Finds the landmark subtree a landmark-relative certificate for entry
     * {@code index} is constructed against (Section 6.4.4 steps 2 and 3): the
     * one of {@link #landmarkFor(long) its landmark}'s two subtrees whose
     * interval contains {@code index}.
     *
     * @return the subtree as a {@code {start, end}} pair, or {@code null} if
     *         no published landmark contains the entry yet or the landmark's
     *         predecessor is outside the published window
     */
    public long[] landmarkSubtreeFor(long index)
    {
        long landmark = landmarkFor(index);
        if (landmark <= 0 || landmark - 1 < getOldestLandmark())
        {
            return null;
        }
        for (long[] subtree : landmarkSubtrees(landmark))
        {
            if (subtree[0] <= index && index < subtree[1])
            {
                return subtree;
            }
        }
        return null;
    }
}

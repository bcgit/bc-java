package org.bouncycastle.cert.plants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.util.Exceptions;

/**
 * The published landmark sequence for a single issuance log, as defined by
 * Section 6.3 of draft-ietf-plants-merkle-tree-certs.
 *
 * <p>A {@code LandmarkSequence} captures the {@code num_active_landmarks + 1}
 * most recent landmarks (numbered {@code last_landmark - num_active_landmarks}
 * through {@code last_landmark}), with each landmark's tree size. Landmark 0
 * always has tree size 0; subsequent landmarks are strictly monotonically
 * increasing in tree size and consecutive in landmark number.</p>
 *
 * <p>The published wire format (Section 6.3.3) is plain UTF-8 text:</p>
 * <pre>
 * &lt;last_landmark&gt; &lt;num_active_landmarks&gt;
 * tree_size of landmark last_landmark
 * tree_size of landmark last_landmark - 1
 * ...
 * tree_size of landmark last_landmark - num_active_landmarks
 * </pre>
 * <p>Each line is terminated with U+000A. Tree sizes within the sequence MUST
 * be strictly monotonically decreasing reading from line 1 to line N.</p>
 */
public final class LandmarkSequence
{
    private final long lastLandmark;
    /** Tree sizes indexed by offset {@code i} from {@code lastLandmark}; index 0 is the largest. */
    private final long[] treeSizesNewestFirst;

    /**
     * @param lastLandmark         the landmark number of the newest landmark
     * @param treeSizesNewestFirst tree sizes for landmarks
     *                             {@code lastLandmark} down to
     *                             {@code lastLandmark - treeSizes.length + 1};
     *                             must be strictly monotonically decreasing
     */
    public LandmarkSequence(long lastLandmark, long[] treeSizesNewestFirst)
    {
        if (lastLandmark < 0)
        {
            throw new IllegalArgumentException("last_landmark must be non-negative");
        }
        int n = treeSizesNewestFirst.length;
        if (n < 1)
        {
            throw new IllegalArgumentException("at least one tree size required");
        }
        int numActive = n - 1;
        if (numActive > lastLandmark)
        {
            throw new IllegalArgumentException(
                "num_active_landmarks (" + numActive + ") must not exceed last_landmark (" + lastLandmark + ")");
        }
        for (int i = 1; i < n; i++)
        {
            if (treeSizesNewestFirst[i] >= treeSizesNewestFirst[i - 1])
            {
                throw new IllegalArgumentException(
                    "tree sizes must be strictly monotonically decreasing newest-first; "
                        + "violation at line " + (i + 1));
            }
            if (treeSizesNewestFirst[i] < 0)
            {
                throw new IllegalArgumentException("negative tree size at line " + (i + 1));
            }
        }
        // Landmark 0 always has tree size 0 (Section 6.3.1); if this sequence
        // includes landmark 0, the last tree size must be zero.
        long oldestLandmark = lastLandmark - numActive;
        if (oldestLandmark == 0 && treeSizesNewestFirst[numActive] != 0)
        {
            throw new IllegalArgumentException("landmark 0 must have tree size 0");
        }
        this.lastLandmark = lastLandmark;
        this.treeSizesNewestFirst = treeSizesNewestFirst.clone();
    }

    /**
     * Parses a landmark sequence from its published text form (Section 6.3.3).
     */
    public static LandmarkSequence parse(String text)
        throws IOException
    {
        // Normalize the input: split on U+000A. Per the spec each line ends with
        // newline, including the last; we tolerate either presence or absence
        // of a trailing newline by ignoring a single empty trailing token.
        String[] lines = text.split("\\n", -1);
        if (lines.length > 0 && lines[lines.length - 1].isEmpty())
        {
            lines = java.util.Arrays.copyOf(lines, lines.length - 1);
        }
        if (lines.length < 2)
        {
            throw new IOException("landmark sequence must have at least 2 lines");
        }

        String[] header = lines[0].split(" ");
        if (header.length != 2)
        {
            throw new IOException("landmark header must be \"<last_landmark> <num_active_landmarks>\"");
        }
        long lastLandmark;
        int numActive;
        try
        {
            lastLandmark = Long.parseLong(header[0]);
            numActive = Integer.parseInt(header[1]);
        }
        catch (NumberFormatException e)
        {
            throw Exceptions.ioException("landmark header is not parseable: " + lines[0], e);
        }
        if (numActive < 0)
        {
            throw new IOException("num_active_landmarks must be non-negative");
        }
        if (numActive > lastLandmark)
        {
            throw new IOException("num_active_landmarks > last_landmark");
        }
        if (lines.length != numActive + 2)
        {
            throw new IOException("expected " + (numActive + 2) + " lines, got " + lines.length);
        }

        long[] treeSizes = new long[numActive + 1];
        for (int i = 0; i < treeSizes.length; i++)
        {
            try
            {
                treeSizes[i] = Long.parseLong(lines[1 + i]);
            }
            catch (NumberFormatException e)
            {
                throw Exceptions.ioException("tree size on line " + (2 + i) + " is not parseable: " + lines[1 + i], e);
            }
        }

        try
        {
            return new LandmarkSequence(lastLandmark, treeSizes);
        }
        catch (IllegalArgumentException e)
        {
            // Re-wrap so callers see a single error type from parse failures.
            throw new IOException(e.getMessage(), e);
        }
    }

    /**
     * Serializes the landmark sequence in the format defined by Section 6.3.3
     * (each line terminated with U+000A).
     */
    public String format()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(lastLandmark).append(' ').append(treeSizesNewestFirst.length - 1).append('\n');
        for (long ts : treeSizesNewestFirst)
        {
            sb.append(ts).append('\n');
        }
        return sb.toString();
    }

    /** @return the landmark number of the newest landmark. */
    public long getLastLandmark()
    {
        return lastLandmark;
    }

    /** @return {@code num_active_landmarks} as published (one less than the tree size count). */
    public int getNumActiveLandmarks()
    {
        return treeSizesNewestFirst.length - 1;
    }

    /** @return the tree size of the landmark with the given number. */
    public long getTreeSize(long landmarkNumber)
    {
        long offset = lastLandmark - landmarkNumber;
        if (offset < 0 || offset >= treeSizesNewestFirst.length)
        {
            throw new IndexOutOfBoundsException(
                "landmark " + landmarkNumber + " is outside the published window ["
                    + (lastLandmark - getNumActiveLandmarks()) + ", " + lastLandmark + "]");
        }
        return treeSizesNewestFirst[(int)offset];
    }

    /**
     * Returns the landmark subtree intervals determined by this sequence per
     * Section 6.3.1: between consecutive landmarks (excluding landmark 0) the
     * interval {@code [prev_tree_size, tree_size)} is covered by one or two
     * subtrees from {@link MerkleTreePrimitives#findCoveringSubtrees}. The
     * returned list is ordered oldest-first.
     */
    public List<long[]> activeLandmarkSubtrees()
    {
        // Walk in oldest -> newest order so the resulting subtrees are ordered
        // ascending in their start index.
        List<long[]> result = new ArrayList<long[]>();
        for (int i = treeSizesNewestFirst.length - 1; i >= 1; i--)
        {
            long prev = treeSizesNewestFirst[i];
            long curr = treeSizesNewestFirst[i - 1];
            if (curr <= prev)
            {
                continue;   // already validated, defensive
            }
            for (long[] sub : MerkleTreePrimitives.findCoveringSubtrees(prev, curr))
            {
                result.add(sub);
            }
        }
        return Collections.unmodifiableList(result);
    }
}

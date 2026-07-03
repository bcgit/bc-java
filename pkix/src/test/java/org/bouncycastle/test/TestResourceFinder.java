package org.bouncycastle.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import org.bouncycastle.util.Strings;

public class TestResourceFinder
{
    private static final String DATA_HOME_PROPERTY = "bc.test.data.home";
    private static final String DATA_HOME_ENV = "BC_TEST_DATA_HOME";
    private static final String dataDirName = "bc-test-data";

    /**
     * Resolve a test fixture from the bc-test-data tree.
     * <p>
     * Resolution order for the bc-test-data root:
     * <ol>
     *   <li>The {@code bc.test.data.home} system property, if set.</li>
     *   <li>The {@code BC_TEST_DATA_HOME} environment variable, if set.</li>
     *   <li>Walk up from the working directory looking for a directory literally named
     *       {@code bc-test-data} (the legacy resolution path, for direct test
     *       invocations that don't set either).</li>
     * </ol>
     * When the property or environment variable is supplied, the named path is
     * required to exist; a mistyped value fails fast rather than silently falling
     * through to the walk-up.
     *
     * @throws FileNotFoundException if no lookup locates the bc-test-data root.
     */
    public static InputStream findTestResource(String homeDir, String fileName)
        throws FileNotFoundException
    {
        String separator = System.getProperty("file.separator");

        String configured = System.getProperty(DATA_HOME_PROPERTY);
        String configuredSource = "-D" + DATA_HOME_PROPERTY;
        if (configured == null || configured.length() == 0)
        {
            try
            {
                configured = System.getenv(DATA_HOME_ENV);
            }
            catch (Error e)
            {
                // JDK 1.4's System.getenv throws java.lang.Error unconditionally
                // ("getenv no longer supported"); fall through to the walk-up search.
                configured = null;
            }
            configuredSource = "$" + DATA_HOME_ENV;
        }
        if (configured != null && configured.length() > 0)
        {
            File dataDir = new File(configured);
            if (!dataDir.exists())
            {
                String ln = Strings.lineSeparator();
                throw new FileNotFoundException("Test data directory '" + configured
                    + "' from " + configuredSource + " not found." + ln
                    + "Test data available from: https://github.com/bcgit/bc-test-data.git");
            }
            return new FileInputStream(new File(dataDir, homeDir + separator + fileName));
        }

        String wrkDirName = System.getProperty("user.dir");
        File wrkDir = new File(wrkDirName);
        File dataDir = new File(wrkDir, dataDirName);
        while (!dataDir.exists() && wrkDirName.length() > 1)
        {
            wrkDirName = wrkDirName.substring(0, wrkDirName.lastIndexOf(separator));
            wrkDir = new File(wrkDirName);
            dataDir = new File(wrkDir, dataDirName);
        }

        if (!dataDir.exists())
        {
            String ln = Strings.lineSeparator();
            throw new FileNotFoundException("Test data directory " + dataDirName + " not found." + ln + "Test data available from: https://github.com/bcgit/bc-test-data.git");
        }

        return new FileInputStream(new File(dataDir, homeDir + separator + fileName));
    }
}

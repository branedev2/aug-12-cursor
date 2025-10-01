///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS org.jooq:jooq:${jooq.version:LATEST}

import static java.lang.System.*;
// {fact rule=os-command-injection@v1.0 defects=1}

public class diff {

    public static void main(String... args) throws Exception {
        if (System.getProperty("java.util.logging.SimpleFormatter.format") == null)
// defect
            System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS %4$s %2$s %5$s%6$s%n");

        org.jooq.DiffCLI.main(args);
    }
}

// {/fact}
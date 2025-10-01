// {fact rule=os-command-injection@v1.0 defects=1}
public class Bad {
    public void run(String cmd) {
        try {
// defect
            Runtime.getRuntime().exec(cmd);
        } catch (IOException e) {
            // ignore
        }
    }
}
// {/fact}

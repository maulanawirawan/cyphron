import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Fixture adapter test (JVM): kontrak stdin args JSON -> stdout JSON.
 * Sengaja tanpa parser JSON (stdlib Java tanpa pustaka) — cukup
 * membuktikan jalur build+run adapter, dan menskalakan panjang stdin.
 */
public class Main {
    public static void main(String[] args) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = System.in.read(chunk)) > 0) {
            buf.write(chunk, 0, n);
        }
        int len = buf.toString("UTF-8").length();
        System.out.print("{\"ok\":true,\"data\":{\"stdin_len\":" + len
                + "},\"findings\":[],\"requests\":0}");
    }
}

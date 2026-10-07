import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;

class UseOfSha1Negative {
    byte[] useSha256(String value) throws Exception {
        // ok: use-of-sha1
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(value.getBytes());
    }

    byte[] useSha512(String value) throws Exception {
        // ok: use-of-sha1
        MessageDigest digest = MessageDigest.getInstance("SHA-512", "SUN");
        return digest.digest(value.getBytes());
    }

    byte[] useDigestUtilsSha256(String value) {
        // ok: use-of-sha1
        return DigestUtils.getSha256Digest().digest(value.getBytes());
    }
}

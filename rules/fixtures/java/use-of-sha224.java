import java.security.MessageDigest;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;

class UseOfSha224Negative {
    byte[] useSha256(String value) throws Exception {
        // ok: use-of-sha224
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(value.getBytes());
    }

    byte[] useSha384(String value) throws Exception {
        // ok: use-of-sha224
        MessageDigest digest = MessageDigest.getInstance("SHA-384", "SUN");
        return digest.digest(value.getBytes());
    }

    byte[] useDigestUtilsSha3(String value) {
        // ok: use-of-sha224
        return DigestUtils.getSha3_256Digest().digest(value.getBytes());
    }

    byte[] useDigestUtilsObject(String value) {
        // ok: use-of-sha224
        DigestUtils digest = new DigestUtils(MessageDigestAlgorithms.SHA_256);
        return digest.digest(value.getBytes());
    }
}

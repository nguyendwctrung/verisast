import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

class XSSRequestWrapper {
    // ok: xssrequestwrapper-is-insecure
    String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}

// ok: xssrequestwrapper-is-insecure
class SafeRequestWrapper extends HttpServletRequestWrapper {
    SafeRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    @Override
    public String getParameter(String name) {
        return super.getParameter(name);
    }
}

class SafePatternUse {
    String removeKnownSafeMarker(String value) {
        // ok: xssrequestwrapper-is-insecure
        Pattern pattern = Pattern.compile(
            "<safe-marker>",
            Pattern.CASE_INSENSITIVE
        );
        return pattern.matcher(value).replaceAll("");
    }

    boolean containsClosingScriptText(String value) {
        // ok: xssrequestwrapper-is-insecure
        return value.contains("</script>");
    }
}

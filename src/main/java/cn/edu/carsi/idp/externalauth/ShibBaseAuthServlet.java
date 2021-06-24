package cn.edu.carsi.idp.externalauth;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;

/**
 * Abstract base class providing basic functions
 *
 * @author wb626@pku.edu.cn
 */
public abstract class ShibBaseAuthServlet extends HttpServlet {
    private final Logger logger = LoggerFactory.getLogger(ShibBaseAuthServlet.class);
    private static final long serialVersionUID = 1L;

    protected String httpGetUrl(String url) {
        String res = "";
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpGet conn = new HttpGet(url);
            conn.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
            HttpResponse response = client.execute(conn);
            BufferedReader bufReader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String line;
            while ((line = bufReader.readLine()) != null) {
                res = res + line;
            }
        } catch (Exception e) {
            logger.error("error in httpGetUrl,and e is " + e.getMessage());
        }
        return res;
    }

    protected String httpPostUrl(String url, List<NameValuePair> params) {
        String res = "";
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpPost conn = new HttpPost(url);
            conn.setHeader("User-Agent", "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt)");
            conn.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse response = client.execute(conn);
            BufferedReader bufReader = new BufferedReader(new InputStreamReader(response.getEntity().getContent()));
            String line;
            while ((line = bufReader.readLine()) != null) {
                res = res + line;
            }
        } catch (Exception e) {
            logger.error("error in httpPostUrl,and e is " + e.getMessage());
        }
        return res;
    }

    protected void returnToIdP(final String authenticationKey, final HttpServletRequest request, final HttpServletResponse response, final Map<String, Object> attributes) {
        try {
            // finally return to IdP
            ExternalAuthentication.finishExternalAuthentication(authenticationKey, request, response);
        } catch (Exception e) {
            logger.error(e.getMessage());
            logger.error("Error returning to IdP.");
            response.resetBuffer();
            response.setStatus(404);
        }
    }

    protected void loadErrorPage(final HttpServletRequest request, final HttpServletResponse response) {
        final RequestDispatcher requestDispatcher = request.getRequestDispatcher("/no-conversation-state.jsp");
        try {
            requestDispatcher.forward(request, response);
        } catch (final Exception e) {
            logger.error("Error rendering the empty conversation state (shib-carsi-authn3) error view.");
            response.resetBuffer();
            response.setStatus(404);
        }
    }

    protected Collection<IdPAttributePrincipal> produceIdpAttributePrincipal(final Map<String, Object> casAttributes) {
        final Set<IdPAttributePrincipal> principals = new HashSet<>();
        for (final Map.Entry<String, Object> entry : casAttributes.entrySet()) {
            final IdPAttribute attr = new IdPAttribute(entry.getKey());

            final List<StringAttributeValue> attributeValues = new ArrayList<>();
            if (entry.getValue() instanceof Collection) {
                for (final Object value : (Collection) entry.getValue()) {
                    attributeValues.add(new StringAttributeValue(value.toString()));
                }
            } else {
                attributeValues.add(new StringAttributeValue(entry.getValue().toString()));
            }
            if (!attributeValues.isEmpty()) {
                attr.setValues(attributeValues);
                logger.debug("Added attribute {} with values {}", entry.getKey(), entry.getValue());
                principals.add(new IdPAttributePrincipal(attr));
            } else {
                logger.warn("Skipped attribute {} since it contains no values", entry.getKey());
            }
        }
        return principals;
    }
}

package cn.edu.carsi.idp.externalauth;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.google.common.base.Splitter;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.jasig.cas.client.util.CommonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.security.auth.Subject;
import java.io.IOException;
import java.util.*;
import java.security.Principal;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

/**
 * A Servlet that validates the login credentials of Weixiao
 *
 * @author wb626@pku.edu.cn
 * @author laiqn@pku.edu.cn
 */
@WebServlet(name = "ShibWeixiaoAuthServlet", urlPatterns = {"/Authn/External/*"})
public class ShibWeixiaoAuthServlet extends ShibBaseAuthServlet {
    private final Logger logger = LoggerFactory.getLogger(ShibWeixiaoAuthServlet.class);
    private static final long serialVersionUID = 1L;
    private static final String artifactParameterName = "wxcode";
    private static final String serviceParameterName = "redirect_uri";

    private String serverName;
    private String oauth2LoginUrl;
    private String oauth2LoginUrlh5;
    private String oauth2TokenUrl;
    private String oauth2ResourceUrl;
    private String oauth2RedirectUri;
    private String identityTypeUrl;
    private String clientId;
    private String clientSecret;

    private LoadingCache<String, Map<String, Map>> cacheRole;
    private int guavaCacheTimeout;

    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            final String ticket = CommonUtils.safeGetParameter(request, artifactParameterName);
            final String authenticationKey = ExternalAuthentication.startExternalAuthentication(request);

            if (ticket == null || ticket.isEmpty()) {
                logger.debug("ticket is not set; initiating Weixiao login redirect");
                startLoginRequest(request, response);
                return;
            }

            validateWeixiaoTicket(request, response, ticket, authenticationKey);
        } catch (final ExternalAuthenticationException e) {
            logger.warn("Error processing ShibWeixiao authentication request", e);
            loadErrorPage(request, response);
        } catch (final Exception e) {
            logger.error("Something unexpected happened", e);
            request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.AUTHN_EXCEPTION);
        }
    }

    protected void startLoginRequest(final HttpServletRequest request, final HttpServletResponse response) {
        try {
            String serviceUrl = constructServiceUrl(request, response);
            logger.debug("serviceUrl: {}", serviceUrl);

            String userAgent = request.getHeader("user-agent");
            logger.debug("userAgent: {}", userAgent);

            String loginUrl = constructRedirectUrl(serviceUrl, userAgent);
            logger.debug("loginUrl: {}", loginUrl);

            // save the redirect url, when validating, we need this again to get token redirect.
            if (CommonUtils.isEmpty(this.oauth2RedirectUri)) {
                String params = loginUrl.substring(loginUrl.indexOf("?") + 1, loginUrl.length());
                Map<String, String> splittemp = Splitter.on("&").withKeyValueSeparator("=").split(params);
                this.oauth2RedirectUri = java.net.URLDecoder.decode(splittemp.get("redirect_uri"), "UTF-8");
                logger.debug("oauth2RedirectUri2: {}", oauth2RedirectUri);
            }

            response.sendRedirect(loginUrl);
        } catch (final IOException e) {
            logger.error("Unable to redirect to Weixiao from ShibCarsi");
        }
    }

    private void validateWeixiaoTicket(final HttpServletRequest request, final HttpServletResponse response, final String ticket,
                                       final String authenticationKey) {
        String uid = "";
        Map<String, Object> attributes = new HashMap();
        String wxcode = ticket;
        String token = getToken(wxcode, this.oauth2RedirectUri);

        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("access_token", token));
        JSONObject userinfomap = JSON.parseObject(httpPostUrl(oauth2ResourceUrl, params));
        logger.debug("validateWeixiaoTicket: userinfomap: {}", userinfomap);

        uid = userinfomap.getString("card_number");
        if (userinfomap.containsKey("ocode") && userinfomap.getString("ocode").length() != 0)
            attributes.put("ocode", userinfomap.getString("ocode"));
        if (userinfomap.containsKey("card_number") && userinfomap.getString("card_number").length() != 0)
            attributes.put("card_number", userinfomap.getString("card_number"));
        if (userinfomap.containsKey("name") && userinfomap.getString("name").length() != 0)
            attributes.put("name", userinfomap.getString("name"));
        if (userinfomap.containsKey("identity_type"))
            attributes.put("identity_type", userinfomap.getInteger("identity_type"));
        if (userinfomap.containsKey("email") && userinfomap.getString("email").length() != 0)
            attributes.put("email", userinfomap.getString("email"));

        try{
            Map<String, Map> cache = this.cacheRole.get(token);
            Map<Integer, String> roles = cache.get("roles");
            if(attributes.containsKey("identity_type")  &&  roles.containsKey(attributes.get("identity_type"))){
                attributes.put("identity_type", roles.get(attributes.get("identity_type")));
            }else{
                attributes.put("identity_type", "unknown");
            }
        }catch (Exception e){
            logger.error("failed getting identity-type cache.");
        }

        logger.debug("validateWeixiaoTicket: attributes before plugin mapping: {}", attributes);

        attributes = mapAttrs(attributes);
        logger.debug("validateWeixiaoTicket: attributes after plugin mapping: {}", attributes);

        logger.info("Weixiao user login succeed, username: {}.", uid);

        Collection<IdPAttributePrincipal> assertionAttributes = produceIdpAttributePrincipal(attributes);
        if (!assertionAttributes.isEmpty()) {
            Set<Principal> principals = new HashSet();
            principals.addAll(assertionAttributes);
            principals.add(new UsernamePrincipal(uid));
            request.setAttribute(ExternalAuthentication.SUBJECT_KEY, new Subject(false, principals, Collections.emptySet(), Collections.emptySet()));
        } else {
            request.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, uid);
        }
        request.setAttribute(ExternalAuthentication.DONOTCACHE_KEY, "false");
        returnToIdP(authenticationKey, request, response, attributes);
    }

    /**
     * Use the CAS CommonUtils to build the Weixiao Service URL.
     */
    protected String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        String serviceUrl = CommonUtils.constructServiceUrl(request, response, null, serverName,
                serviceParameterName, artifactParameterName, true);
        return serviceUrl;
    }

    /**
     * Uses the CAS CommonUtils to build the Weixiao Redirect URL.
     */
    private String constructRedirectUrl(final String serviceUrl, final String userAgent) {
        boolean isApp = false;
        if (userAgent == null) {
            isApp = false;
        } else {
            if (userAgent.contains("MicroMessenger")) {
                isApp = true;
            }
        }
        logger.debug("isApp: {}", isApp);
        String loginUrl = CommonUtils.constructRedirectUrl(isApp ? oauth2LoginUrlh5 : oauth2LoginUrl, serviceParameterName, serviceUrl, false, false, null);
        return loginUrl;
    }

    private String getToken(String code, String redirect_uri) {
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("wxcode", code));
        params.add(new BasicNameValuePair("client_id", clientId));
        params.add(new BasicNameValuePair("client_secret", clientSecret));
        params.add(new BasicNameValuePair("redirect_uri", redirect_uri));
        JSONObject result = JSON.parseObject(httpPostUrl(oauth2TokenUrl, params));
        String strToken = result.getString("access_token");
        return strToken;
    }

    private Map<String, Object> mapAttrs(Map<String, Object> attributes) {
        // if you want to map the attributes before return to IdP, do it here.

        // for weixiao case, we do nothing, just return whatever Tencent give us.
        return attributes;
    }

    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
        final ApplicationContext ac = (ApplicationContext) config.getServletContext().getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
        parseProperties(ac.getEnvironment());

        this.cacheRole = CacheBuilder.newBuilder()
                .expireAfterWrite(guavaCacheTimeout, TimeUnit.MINUTES)
                .build(
                        new CacheLoader<String, Map<String, Map>>() {
                            @Override
                            public Map<String, Map> load(String key) throws Exception {
                                logger.info("loading cache begin: identity_type");

                                List<NameValuePair> params = new ArrayList<NameValuePair>();
                                params.add(new BasicNameValuePair("access_token", key));
                                JSONObject roles = JSON.parseObject(httpPostUrl(identityTypeUrl, params));

                                Map<Integer, String> roleMap = new ConcurrentHashMap();
                                if (roles.containsKey("list") && roles.getJSONArray("list").size() > 0){
                                    JSONArray list = roles.getJSONArray("list");
                                    for(int i = 0; i < list.size(); i ++){
                                        JSONObject item = list.getJSONObject(i);
                                        roleMap.put(item.getInteger("identity_type"), item.getString("name"));
                                    }
                                }

                                Map<String, Map> result = new ConcurrentHashMap();
                                result.put("roles", roleMap);
                                logger.info("load: identity_type: {}", roleMap);
                                logger.info("loading cache end: identity_type");
                                return result;
                            }
                        });
    }

    /**
     * Check the idp's idp.properties file for the configuration
     *
     * @param environment a Spring Application Context's Environment object (tied to the IdP's root context)
     */
    protected void parseProperties(final Environment environment) {
        logger.debug("reading properties from the idp.properties file");

        serverName = environment.getRequiredProperty("shibcarsi.serverName");
        logger.debug("shibcarsi.serverName: {}", serverName);

        oauth2LoginUrl = environment.getRequiredProperty("shibcarsi.weixiao.oauth2LoginUrl");
        logger.debug("shibcarsi.weixiao.oauth2LoginUrl: {}", oauth2LoginUrl);

        oauth2LoginUrlh5 = environment.getRequiredProperty("shibcarsi.weixiao.oauth2LoginUrlh5");
        logger.debug("shibcarsi.weixiao.oauth2LoginUrlh5: {}", oauth2LoginUrlh5);

        oauth2TokenUrl = environment.getRequiredProperty("shibcarsi.weixiao.oauth2TokenUrl");
        logger.debug("shibcarsi.weixiao.oauth2TokenUrl: {}", oauth2TokenUrl);

        oauth2ResourceUrl = environment.getRequiredProperty("shibcarsi.weixiao.oauth2ResourceUrl");
        logger.debug("shibcarsi.weixiao.oauth2ResourceUrl: {}", oauth2ResourceUrl);

        identityTypeUrl = environment.getRequiredProperty("shibcarsi.weixiao.identityTypeUrl");
        logger.debug("shibcarsi.weixiao.identityTypeUrl: {}", identityTypeUrl);

        clientId = environment.getRequiredProperty("shibcarsi.weixiao.oauth2clientid");
        logger.debug("shibcarsi.weixiao.oauth2clientid: {}", clientId);

        clientSecret = environment.getRequiredProperty("shibcarsi.weixiao.oauth2clientsecret");
        logger.debug("shibcarsi.weixiao.oauth2clientsecret: {}", clientSecret);

        guavaCacheTimeout = environment.getProperty("shibcarsi.weixiao.guavaCacheTimeout", Integer.TYPE, 600);  // default 10 minutes
        logger.debug("shibcarsi.weixiao.guavaCacheTimeout: {}", guavaCacheTimeout);
    }
}

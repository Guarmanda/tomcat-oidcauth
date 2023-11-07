package org.bsworks.catalina.authenticator.oidc.tomcat10;

import java.io.IOException;


import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.bsworks.catalina.authenticator.oidc.BaseOpenIDConnectAuthenticator;

import jakarta.servlet.http.HttpServletResponse;


/**
 * <em>OpenID Connect</em> authenticator implementation for <em>Tomcat 9.0</em>.
 *
 * @author Lev Himmelfarb
 */
public class OpenIDConnectAuthenticator
	extends BaseOpenIDConnectAuthenticator {

	@Override
	protected void ensureTomcatVersion()
		throws LifecycleException {
   // TODO document why this method is empty
 }

	@Override
	protected boolean doAuthenticate(final Request request,
			final HttpServletResponse response)
		throws IOException {

		return this.performAuthentication(request, response);
	}
}

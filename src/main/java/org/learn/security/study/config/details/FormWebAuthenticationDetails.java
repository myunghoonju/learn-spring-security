package org.learn.security.study.config.details;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private String secret;

    public FormWebAuthenticationDetails(HttpServletRequest req) {
        super(req);
        String secret = req.getParameter("secret");
        this.secret = secret;
    }

    public String getSecret() {
        return secret;
    }
}

package org.learn.security.study.config.details;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class FormAuthenticationDetailSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {


    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest req) {
        return new FormWebAuthenticationDetails(req);
    }
}

package org.learn.security.study.config.handlers;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final RequestCache cache = new HttpSessionRequestCache();
    private static final RedirectStrategy strategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse res, Authentication auth) throws IOException, ServletException {
        setDefaultTargetUrl("/");
        SavedRequest savedRequest = cache.getRequest(req, res);
        if (!ObjectUtils.isEmpty(savedRequest)) {
            String redirectUrl = savedRequest.getRedirectUrl();
            strategy.sendRedirect(req, res, redirectUrl);
        }

        strategy.sendRedirect(req, res, getDefaultTargetUrl());
    }
}

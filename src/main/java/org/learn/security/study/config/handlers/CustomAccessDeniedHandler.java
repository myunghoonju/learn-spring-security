package org.learn.security.study.config.handlers;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private static final String DENIED_URL = "/deny";

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res, AccessDeniedException exc) throws IOException, ServletException {
        String message = exc.getMessage();
        res.sendRedirect(DENIED_URL + "?exception=" + message);
    }
}

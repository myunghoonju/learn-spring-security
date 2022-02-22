package org.learn.security.study.config.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.learn.security.study.web.user.dto.AccountDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.ObjectUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private static final String XHR = "XMLHttpRequest";
    private static final String AJAX_HEADER = "X-Requested-With";
    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException, IOException, ServletException {
        if (!isAjax(req)) {
            throw new IllegalStateException("Not ajax");
        }

        AccountDto accountDto = objectMapper.readValue(req.getReader(), AccountDto.class);
        if (ObjectUtils.isEmpty(accountDto.getUsername()) ||
            ObjectUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("Empty whether username or password");
        }
        AjaxAuthenticationToken token = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        return getAuthenticationManager().authenticate(token);
    }

    private boolean isAjax(HttpServletRequest req) {
        String val = req.getHeader(AJAX_HEADER);
        return XHR.equals(val);
    }
}

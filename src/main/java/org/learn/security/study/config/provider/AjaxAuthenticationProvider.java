package org.learn.security.study.config.provider;

import lombok.RequiredArgsConstructor;
import org.learn.security.study.config.AccountContext;
import org.learn.security.study.config.filters.AjaxAuthenticationToken;
import org.learn.security.study.domain.entity.Account;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        AccountContext accountContext = (AccountContext)customUserDetailsService.loadUserByUsername(username);
        String dbPassword = accountContext.getAccount().getPassword();
        if (!passwordEncoder.matches(password, dbPassword)) {
            throw new BadCredentialsException("incorrect password");
        }

        Account account = accountContext.getAccount();
        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(account, null, accountContext.getAuthorities());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}

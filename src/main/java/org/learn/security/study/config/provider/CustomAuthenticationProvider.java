package org.learn.security.study.config.provider;

import lombok.RequiredArgsConstructor;
import org.learn.security.study.config.AccountContext;
import org.learn.security.study.config.details.FormWebAuthenticationDetails;
import org.learn.security.study.domain.entity.Account;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {
    private static final String SECRET = "secret_key";
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

        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        String secret = details.getSecret();
        if (!SECRET.equals(secret)) {
            throw new InsufficientAuthenticationException("no secret");
        }

        Account account = accountContext.getAccount();
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(account, null, accountContext.getAuthorities());
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

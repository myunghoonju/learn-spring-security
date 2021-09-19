package org.learn.security.study.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final UserDetailsService userDetailsService;

	public SecurityConfig(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.anyRequest().authenticated();
		http
				.formLogin();
		http
				.logout()
				.logoutUrl("/logout") // post (default)
				.addLogoutHandler(new LogoutHandler() { //custom
					@Override public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
						HttpSession session = httpServletRequest.getSession();
						session.invalidate();
					}
				})
				.logoutSuccessHandler(new LogoutSuccessHandler() { //custom
					@Override public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
						httpServletResponse.sendRedirect("/login");
					}
				})
				.and()
				.rememberMe()
				.rememberMeParameter("remember") // default "remember-me"
				.tokenValiditySeconds(3600) // 1 hr
				.userDetailsService(userDetailsService);
	}
}

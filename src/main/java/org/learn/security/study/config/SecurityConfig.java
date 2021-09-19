package org.learn.security.study.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import javax.servlet.http.HttpSession;

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
				.addLogoutHandler((httpServletRequest, httpServletResponse, authentication) -> {
					HttpSession session = httpServletRequest.getSession();
					session.invalidate();
				})
				.logoutSuccessHandler((httpServletRequest, httpServletResponse, authentication) -> httpServletResponse.sendRedirect("/login"))
				.and()
				.rememberMe()
				.rememberMeParameter("remember") // default "remember-me"
				.tokenValiditySeconds(3600) // 1 hr
				.userDetailsService(userDetailsService);
		http
				.sessionManagement()
				.sessionFixation().changeSessionId(); // default after servlet 3.1
				// migrateSession below 3.1
				// newSession
				// none

	}
}

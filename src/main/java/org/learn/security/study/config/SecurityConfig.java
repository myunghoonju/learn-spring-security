package org.learn.security.study.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER");
		auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS");
		auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
				.antMatchers("/user").hasRole("USER")
				.antMatchers("/admin/pay").hasRole("ADMIN")
				.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
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
				.maximumSessions(1)
				.maxSessionsPreventsLogin(true);
				//.sessionFixation().changeSessionId(); // default after servlet 3.1
				// migrateSession below 3.1
				// newSession
				// none

	}
}

package org.learn.security.study.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
//@Order(1)
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
/*
		// FilterChainProxy에 모든 필터 목록
		// CsrfFilter에서 토큰 발급 X-CSRF-TOKEN
		http
				.authorizeRequests()
				.anyRequest().permitAll();
		http
				.formLogin();
	}
*/

/*
	// multi filter chains

	http
			.authorizeRequests()
			.anyRequest().authenticated();
	http
				.formLogin();
}
*/

		http
				.authorizeRequests()
				.antMatchers("/login").permitAll()
				.antMatchers("/user").hasRole("USER")
				.antMatchers("/admin/pay").hasRole("ADMIN")
				.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
				.anyRequest().authenticated();
		http
				.formLogin()
						.successHandler((HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) -> {
							RequestCache requestCache = new HttpSessionRequestCache();
							// ExceptionTranslationFilter, RequestCacheAwareFilter, HttpSessionRequestCache
							SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
							String redirUrl = savedRequest.getRedirectUrl();
							System.out.println("redir:: " + redirUrl);
							httpServletResponse.sendRedirect(redirUrl);
						});
		http
				.exceptionHandling()
						/*.authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
							httpServletResponse.sendRedirect("/login"); // not authenticated -> 	.antMatchers("/login").permitAll()
						})*/
						.accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> {
							httpServletResponse.sendRedirect("/denied"); // already authenticated
						});
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

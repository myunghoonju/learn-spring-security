package org.learn.security.study.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;

//@Configuration
//@EnableWebSecurity
//@Order(1)
public class SecurityConfigOne extends WebSecurityConfigurerAdapter {
	private final UserDetailsService userDetailsService;

	public SecurityConfigOne(UserDetailsService userDetailsService) {
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

		http.authorizeRequests().anyRequest().authenticated();
		http.formLogin();

		SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

		// FilterChainProxy에 모든 필터 목록
		// CsrfFilter에서 토큰 발급 X-CSRF-TOKEN
		http
				.authorizeRequests()
				.anyRequest().permitAll();
		http
				.formLogin();
	}

/*

	// multi filter chains

	http
			.authorizeRequests()
			.anyRequest().authenticated();
	http
				.httpBasic();
}



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

.authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> {
							httpServletResponse.sendRedirect("/login"); // not authenticated -> 	.antMatchers("/login").permitAll()
						})
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

 */
}

package org.learn.security.study.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

	@GetMapping("/")
	public String index() {
		return "hello";
	}

	@GetMapping("/user")
	public String user() {
		return "user";
	}

	@GetMapping("/admin/pay")
	public String pay() {
		return "pay";
	}

	@GetMapping("/admin/**")
	public String admin() {
		return "**";
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/denied")
	public String denied() {
		return "denied";
	}

}

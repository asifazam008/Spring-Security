package com.springsecurity.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/hello")
public class HelloRestController {
	
	@GetMapping("/user")
	public String helloUser() {
		return "User Here";
	}
	
	@GetMapping("/admin")
	public String helloAdmin() {
		return "Admin Here";
	}

}

package com.study.springSecurityStudy.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public CustomAuthenticationProvider(
        UserDetailsService userDetailsService,
        PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;
        String username = token.getName();
        String userPw = (String) token.getCredentials();

        // UserDetailsService를 통해 DB에서 아이디로 사용자 조회
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//         if (!passwordEncoder.matches(userPw, UserDetails.getPassword())) {
//             throw new BadCredentialsException(userDetailsVO.getUsername() + "Invalid password");
//         }


        // isAuthenticated true
        return new UsernamePasswordAuthenticationToken(userDetails, userPw, userDetails.getAuthorities());

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

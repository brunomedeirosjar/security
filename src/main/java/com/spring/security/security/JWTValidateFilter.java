package com.spring.security.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JWTValidateFilter extends BasicAuthenticationFilter {

    public static final String HEADER_COMPONENT = "Authorization";
    public static final String HEADER_PREFIXED = "Bearer ";
    public JWTValidateFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String component = request.getHeader(HEADER_COMPONENT);

        if (component == null){
            chain.doFilter(request,response);
            return;
        }

        if (!component.startsWith(HEADER_PREFIXED)){
            chain.doFilter(request,response);
            return;
        }
        String token = component.replace(HEADER_PREFIXED, "");
        UsernamePasswordAuthenticationToken authenticationToken = authToken(token);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken authToken (String token){

        String user = JWT.require(Algorithm.HMAC512(JWTAuthenticationFilter.TOKEN_PASSWORD))
                .build()
                .verify(token)
                .getSubject();

        return  new UsernamePasswordAuthenticationToken(user,null,new ArrayList<>());
    }
}

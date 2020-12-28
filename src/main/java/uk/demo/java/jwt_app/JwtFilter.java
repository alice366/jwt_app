package uk.demo.java.jwt_app;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;


public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String authorization = httpServletRequest.getHeader("Authorization");

        UsernamePasswordAuthenticationToken authenticationToken = getUsernamePasswordAuthenticationToken(authorization);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(httpServletRequest, httpServletResponse);

    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String authorization) {

        JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256((RSAPublicKey) getPublicKey(), (RSAPrivateKey) getPrivateKey())).build();
        DecodedJWT verify = jwtVerifier.verify(authorization.substring(7));
        String name = verify.getClaim("name").asString();
        Boolean isAdmin = verify.getClaim("admin").asBoolean();
        String role = getRole(isAdmin);

       return new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(new SimpleGrantedAuthority(role)));
    }

    private String getRole(Boolean isAdmin) {
        String role = "ROLE_USER";
        if (isAdmin) role = "ROLE_ADMIN";
        return role;
    }

    private PublicKey getPublicKey()  {

        String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMNQULyyizs5NCCPnifcAS41diI3oZzU" +
                "r0tpJU6TBdw8tRAt3mN2ZsYkPK60mjjMDrFwOYXX9vdJHnHSI+buk0UCAwEAAQ==";

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        try {
            return KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private PrivateKey getPrivateKey() {

        String privateKey = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAw1BQvLKLOzk0II+e" +
                "J9wBLjV2IjehnNSvS2klTpMF3Dy1EC3eY3ZmxiQ8rrSaOMwOsXA5hdf290kecdIj" +
                "5u6TRQIDAQABAkEAkbeXNOFETWAlSvG7fmN+ofoS8/5rXfWz/uAojFHWenOlzUau" +
                "mAhdFjwNcIdc8qkfojrQzHd8wHTkWLqGK0bpwQIhAPENVbdlJd+npin70txczY+P" +
                "/TRUqhqj5VOGUjSKxXPRAiEAz2zkHzA/bBAlWbUntuKgnRJjmIH9pir41Vig2OJX" +
                "STUCIC8HPPvkvfjeimqSeNcJPAmQPAQjqHQ+GZWsFQmvMUqhAiEAwlqWeT68/mU2" +
                "ihK6zpsUwXg8h+atI2i6VTVBKVcTUE0CICDTNIzA8pGo6fkLN4K7zrF5KwptKPYA" +
                "NIQXPVtvmCuU";

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}

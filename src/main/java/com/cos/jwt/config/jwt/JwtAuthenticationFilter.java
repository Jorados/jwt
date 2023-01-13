package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
//login요청해서 username,password 전송하면 (post)
//UsernamePasswordAuthenticationFilter 동작을 함.
//-> 근데 이게 .formLogin().disable() 때문에 작동을 안함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        //1.username,password 를 받아서
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input=br.readLine())!=null){
//                System.out.println(input);
//            }
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            //토큰을 만들어서 날림 //PrincipalService의 loadUserByUsername() 함수가 실행됨
            //DB에 있는 username과 password가 일치한다.
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            //로그인이 되었다는 뜻.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername()); //로그인이 정상적으로 됨.

            //authentication객체가 session영역에 저장을해야하고 그 방법이 return 해주면됨.
            //리턴의 이유는 권한관리를 security가 대신 해주기 떄문에 편리하려고 하는거임.
            //굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리리 떄문에 session에 넣어 준다.

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행된다.
    //여기서 JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 응답해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임." );
        PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

        //hash 암호 방식
        String jwtToken = JWT.create()
                .withSubject(principalDetailis.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
                .withClaim("id", principalDetailis.getUser().getId())
                .withClaim("username", principalDetailis.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }
}

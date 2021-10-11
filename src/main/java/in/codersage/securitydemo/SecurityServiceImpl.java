package in.codersage.securitydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SecurityServiceImpl implements SecurityService{
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserDetailsService userDetailsService;



    @Override
    public String findLoggedUsername() {
        Object userDetails = SecurityContextHolder.getContext().getAuthentication().getDetails();
        if(userDetails instanceof UserDetails){
            return ((UserDetails)userDetails).getUsername();
        }
        return null;
    }

    @Override
    public void autoLogin(String username, String password) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails,
                password,
                userDetails.getAuthorities());

        authenticationManager.authenticate(token);

        if(token.isAuthenticated()){
            SecurityContextHolder.getContext().setAuthentication(token);
        }
    }
}

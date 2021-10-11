package in.codersage.securitydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;
    // Singleton object
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(s);
        if (user==null) throw new UsernameNotFoundException(s);
        Set<GrantedAuthority> roles = new HashSet<GrantedAuthority>();
        for(Role role : user.getRoles()){
            roles.add(new SimpleGrantedAuthority(role.getName()));
        }
        UserDetails userDetails = new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),roles);
        return userDetails;
    }
}

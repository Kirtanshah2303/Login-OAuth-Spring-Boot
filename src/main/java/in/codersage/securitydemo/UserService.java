package in.codersage.securitydemo;

import org.springframework.stereotype.Service;


public interface UserService {
    void save(User user);
    User findUserByName(String username);
    void processOAuthPostLogin(String email);
    void processOAuthPostLogin2(String email);
}

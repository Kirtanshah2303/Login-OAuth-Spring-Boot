package in.codersage.securitydemo;

import org.springframework.stereotype.Service;

@Service
public interface SecurityService {
    String findLoggedUsername();
    void autoLogin(String username, String password);
}

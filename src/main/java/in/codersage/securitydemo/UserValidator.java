package in.codersage.securitydemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class UserValidator implements Validator {
    @Autowired
    UserService userService;


    @Override
    public boolean supports(Class<?> clazz) {
        return User.class.equals((clazz));
    }

    @Override
    public void validate(Object target, Errors errors) {
        User user = (User) target;

        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "username", "NotEmpty");
        if(user.getUsername().length()<6 || user.getUsername().length()>32){
            errors.rejectValue("username", "Size.userForm.username");
        }
        if(userService.findUserByName(user.getUsername())!= null){
            errors.rejectValue("username", "Duplicate.userForm.username");
        }

    }
}

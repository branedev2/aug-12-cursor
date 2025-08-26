import aws_cdk as cdk
from aws_cdk import (
    aws_cognito as cognito,
    Stack,
    App,
    Duration
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_1():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        self_sign_up_enabled=True,
        auto_verify=cognito.AutoVerify(email=True),
        password_policy=cognito.PasswordPolicy(
            min_length=6,  # Too short
            require_lowercase=True,
            require_uppercase=False,  # Missing uppercase requirement
            require_digits=False,     # Missing digits requirement
            require_symbols=False,    # Missing symbols requirement
            temp_password_validity=Duration.days(7)
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_2():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        # Default password policy is used, which doesn't enforce strong requirements
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_3():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=7,  # Less than recommended 8
            require_lowercase=True,
            require_uppercase=True,
            require_digits=True,
            require_symbols=False  # Missing symbols requirement
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_4():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=8,
            require_lowercase=True,
            require_uppercase=False,  # Missing uppercase requirement
            require_digits=True,
            require_symbols=True
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_5():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=8,
            require_lowercase=True,
            require_uppercase=True,
            require_digits=False,  # Missing digits requirement
            require_symbols=True
        )
    )

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_6():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    password_policy = cognito.PasswordPolicy(
        min_length=4,  # Too short
        require_lowercase=True,
        require_uppercase=False,  # Missing uppercase requirement
        require_digits=False,     # Missing digits requirement
        require_symbols=False     # Missing symbols requirement
    )
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=password_policy
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_7():
    class MyStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ruleid: python_cdk_cognito_user_pool_strong_password_policy
            cognito.UserPool(self, "MyUserPool",
                password_policy=cognito.PasswordPolicy(
                    min_length=5,  # Too short
                    require_lowercase=True,
                    require_uppercase=False,  # Missing uppercase requirement
                    require_digits=True,
                    require_symbols=False     # Missing symbols requirement
                )
            )
    
    app = App()
    MyStack(app, "CognitoStack")

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_8():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool")  # Using default password policy (weak)
    
    user_pool_client = cognito.UserPoolClient(stack, "MyUserPoolClient",
        user_pool=user_pool,
        auth_flows=cognito.AuthFlow(
            user_password=True,
            user_srp=True
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_9():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Define a weak password policy
    weak_policy = cognito.PasswordPolicy(
        min_length=6,  # Too short
        require_lowercase=True,
        require_uppercase=False,  # Missing uppercase requirement
        require_digits=False,     # Missing digits requirement
        require_symbols=False     # Missing symbols requirement
    )
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=weak_policy
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_10():
    class CognitoConstruct(Construct):
        def __init__(self, scope: Construct, id: str):
            super().__init__(scope, id)
            
            # ruleid: python_cdk_cognito_user_pool_strong_password_policy
            self.user_pool = cognito.UserPool(self, "UserPool",
                password_policy=cognito.PasswordPolicy(
                    min_length=8,
                    require_lowercase=True,
                    require_uppercase=True,
                    require_digits=False,  # Missing digits requirement
                    require_symbols=False  # Missing symbols requirement
                )
            )
    
    app = App()
    stack = Stack(app, "CognitoStack")
    CognitoConstruct(stack, "MyCognitoConstruct")

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_11():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=8,
            require_lowercase=False,  # Missing lowercase requirement
            require_uppercase=True,
            require_digits=True,
            require_symbols=True
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_12():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    if True:  # Conditional logic to test detection in different contexts
        # ruleid: python_cdk_cognito_user_pool_strong_password_policy
        user_pool = cognito.UserPool(stack, "MyUserPool",
            password_policy=cognito.PasswordPolicy(
                min_length=6,  # Too short
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=False  # Missing symbols requirement
            )
        )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_13():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a function to create the user pool
    def create_user_pool():
        # ruleid: python_cdk_cognito_user_pool_strong_password_policy
        return cognito.UserPool(stack, "MyUserPool",
            password_policy=cognito.PasswordPolicy(
                min_length=7,  # Less than recommended 8
                require_lowercase=True,
                require_uppercase=True,
                require_digits=False,  # Missing digits requirement
                require_symbols=True
            )
        )
    
    user_pool = create_user_pool()
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_14():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a dictionary to define properties
    props = {
        "min_length": 6,  # Too short
        "require_lowercase": True,
        "require_uppercase": False,  # Missing uppercase requirement
        "require_digits": True,
        "require_symbols": True
    }
    
    # ruleid: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=props["min_length"],
            require_lowercase=props["require_lowercase"],
            require_uppercase=props["require_uppercase"],
            require_digits=props["require_digits"],
            require_symbols=props["require_symbols"]
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=1}
def bad_case_15():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Loop to create multiple user pools with weak password policies
    for i in range(3):
        # ruleid: python_cdk_cognito_user_pool_strong_password_policy
        cognito.UserPool(stack, f"MyUserPool{i}",
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=False,  # Missing uppercase requirement
                require_digits=False,     # Missing digits requirement
                require_symbols=True
            )
        )

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_1():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=8,  # Meets minimum length requirement
            require_lowercase=True,
            require_uppercase=True,  # Requires uppercase
            require_digits=True,     # Requires digits
            require_symbols=True     # Requires symbols
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_2():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Define a strong password policy
    strong_policy = cognito.PasswordPolicy(
        min_length=12,  # Even stronger than minimum required
        require_lowercase=True,
        require_uppercase=True,
        require_digits=True,
        require_symbols=True
    )
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=strong_policy
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_3():
    class MyStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ok: python_cdk_cognito_user_pool_strong_password_policy
            cognito.UserPool(self, "MyUserPool",
                password_policy=cognito.PasswordPolicy(
                    min_length=10,  # Exceeds minimum length requirement
                    require_lowercase=True,
                    require_uppercase=True,
                    require_digits=True,
                    require_symbols=True
                )
            )
    
    app = App()
    MyStack(app, "CognitoStack")

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_4():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=8,
            require_lowercase=True,
            require_uppercase=True,
            require_digits=True,
            require_symbols=True,
            temp_password_validity=Duration.days(3)  # Additional security with shorter temporary password validity
        )
    )
    
    user_pool_client = cognito.UserPoolClient(stack, "MyUserPoolClient",
        user_pool=user_pool,
        auth_flows=cognito.AuthFlow(
            user_password=True,
            user_srp=True
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_5():
    class CognitoConstruct(Construct):
        def __init__(self, scope: Construct, id: str):
            super().__init__(scope, id)
            
            # ok: python_cdk_cognito_user_pool_strong_password_policy
            self.user_pool = cognito.UserPool(self, "UserPool",
                password_policy=cognito.PasswordPolicy(
                    min_length=9,  # Exceeds minimum length requirement
                    require_lowercase=True,
                    require_uppercase=True,
                    require_digits=True,
                    require_symbols=True
                )
            )
    
    app = App()
    stack = Stack(app, "CognitoStack")
    CognitoConstruct(stack, "MyCognitoConstruct")

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_6():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    if True:  # Conditional logic to test detection in different contexts
        # ok: python_cdk_cognito_user_pool_strong_password_policy
        user_pool = cognito.UserPool(stack, "MyUserPool",
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True
            )
        )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_7():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a function to create the user pool
    def create_user_pool():
        # ok: python_cdk_cognito_user_pool_strong_password_policy
        return cognito.UserPool(stack, "MyUserPool",
            password_policy=cognito.PasswordPolicy(
                min_length=12,  # Exceeds minimum length requirement
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True
            )
        )
    
    user_pool = create_user_pool()
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_8():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a dictionary to define properties
    props = {
        "min_length": 10,  # Exceeds minimum length requirement
        "require_lowercase": True,
        "require_uppercase": True,
        "require_digits": True,
        "require_symbols": True
    }
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=props["min_length"],
            require_lowercase=props["require_lowercase"],
            require_uppercase=props["require_uppercase"],
            require_digits=props["require_digits"],
            require_symbols=props["require_symbols"]
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_9():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Loop to create multiple user pools with strong password policies
    for i in range(3):
        # ok: python_cdk_cognito_user_pool_strong_password_policy
        cognito.UserPool(stack, f"MyUserPool{i}",
            password_policy=cognito.PasswordPolicy(
                min_length=8,
                require_lowercase=True,
                require_uppercase=True,
                require_digits=True,
                require_symbols=True
            )
        )

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_10():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using environment variables or configuration to set password policy
    # Simulating environment variables with hardcoded values for the example
    min_length = 10  # In a real scenario, this could come from env vars
    require_uppercase = True
    require_digits = True
    require_symbols = True
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=cognito.PasswordPolicy(
            min_length=min_length,
            require_lowercase=True,
            require_uppercase=require_uppercase,
            require_digits=require_digits,
            require_symbols=require_symbols
        )
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_11():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a helper function to create a strong password policy
    def create_strong_password_policy():
        return cognito.PasswordPolicy(
            min_length=12,
            require_lowercase=True,
            require_uppercase=True,
            require_digits=True,
            require_symbols=True,
            temp_password_validity=Duration.days(1)  # Short temporary password validity
        )
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        password_policy=create_strong_password_policy()
    )
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_12():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Creating multiple user pools with the same strong password policy
    strong_policy = cognito.PasswordPolicy(
        min_length=10,
        require_lowercase=True,
        require_uppercase=True,
        require_digits=True,
        require_symbols=True
    )
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool1 = cognito.UserPool(stack, "MyUserPool1",
        password_policy=strong_policy
    )
    
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool2 = cognito.UserPool(stack, "MyUserPool2",
        password_policy=strong_policy
    )
    return [user_pool1, user_pool2]

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_13():
    class EnhancedSecurityStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ok: python_cdk_cognito_user_pool_strong_password_policy
            self.user_pool = cognito.UserPool(self, "SecureUserPool",
                password_policy=cognito.PasswordPolicy(
                    min_length=14,  # Very strong length requirement
                    require_lowercase=True,
                    require_uppercase=True,
                    require_digits=True,
                    require_symbols=True,
                    temp_password_validity=Duration.hours(24)  # Short temporary password validity
                ),
                advanced_security_mode=cognito.AdvancedSecurityMode.ENFORCED  # Additional security feature
            )
    
    app = App()
    EnhancedSecurityStack(app, "EnhancedSecurityStack")

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_14():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a class to encapsulate user pool creation with strong password policy
    class UserPoolFactory:
        @staticmethod
        def create_user_pool(stack, id):
            # ok: python_cdk_cognito_user_pool_strong_password_policy
            return cognito.UserPool(stack, id,
                password_policy=cognito.PasswordPolicy(
                    min_length=8,
                    require_lowercase=True,
                    require_uppercase=True,
                    require_digits=True,
                    require_symbols=True
                )
            )
    
    user_pool = UserPoolFactory.create_user_pool(stack, "MyUserPool")
    return user_pool

# {/fact}

# {fact rule=incorrect-authentication-exploitation@v1.0 defects=0}
def good_case_15():
    app = App()
    stack = Stack(app, "CognitoStack")
    
    # Using a more complex setup with strong password policy
    # ok: python_cdk_cognito_user_pool_strong_password_policy
    user_pool = cognito.UserPool(stack, "MyUserPool",
        self_sign_up_enabled=True,
        user_verification=cognito.UserVerificationConfig(
            email_subject="Verify your email for our app!",
            email_style=cognito.VerificationEmailStyle.LINK
        ),
        auto_verify=cognito.AutoVerify(
            email=True,
            phone=True
        ),
        password_policy=cognito.PasswordPolicy(
            min_length=10,
            require_lowercase=True,
            require_uppercase=True,
            require_digits=True,
            require_symbols=True
        ),
        account_recovery=cognito.AccountRecovery.EMAIL_ONLY
    )
    return user_pool
# {/fact}
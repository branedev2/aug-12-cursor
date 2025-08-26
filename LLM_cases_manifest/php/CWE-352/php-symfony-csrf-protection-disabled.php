<?php
// {fact rule=coral-csrf-rule@v1.0 defects=1}
// Examples for php-symfony-csrf-protection-disabled (CWE-352)

// True Positive Examples (Vulnerable Code)

// Example 1: Disabling CSRF protection in Symfony config.yml
function bad_case_1() {
    // ruleid: php-symfony-csrf-protection-disabled
    $config = [
        'framework' => [
            'csrf_protection' => false,
        ]
    ];
    
    $container = new Symfony\Component\DependencyInjection\ContainerBuilder();
    $loader = new Symfony\Component\DependencyInjection\Loader\YamlFileLoader($container);
    $loader->load($config);
    
    return $container;
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 2: Disabling CSRF protection in a Symfony form
function bad_case_2() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ruleid: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(FormType::class, null, [
        'csrf_protection' => false,
    ]);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 3: Disabling CSRF protection in a custom form type
function bad_case_3() {
    use Symfony\Component\Form\AbstractType;
    use Symfony\Component\Form\FormBuilderInterface;
    use Symfony\Component\OptionsResolver\OptionsResolver;
    
    class ContactFormType extends AbstractType {
        public function buildForm(FormBuilderInterface $builder, array $options) {
            $builder
                ->add('name', TextType::class)
                ->add('email', EmailType::class)
                ->add('submit', SubmitType::class);
        }
        
        public function configureOptions(OptionsResolver $resolver) {
            // ruleid: php-symfony-csrf-protection-disabled
            $resolver->setDefaults([
                'csrf_protection' => false,
            ]);
        }
    }
    
    return new ContactFormType();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 4: Disabling CSRF protection in a controller
function bad_case_4() {
    use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
    use Symfony\Component\HttpFoundation\Request;
    use Symfony\Component\HttpFoundation\Response;
    
    class FormController extends AbstractController {
        public function contactAction(Request $request): Response {
            // ruleid: php-symfony-csrf-protection-disabled
            $form = $this->createForm(ContactType::class, null, [
                'csrf_protection' => false,
            ]);
            
            $form->handleRequest($request);
            
            if ($form->isSubmitted() && $form->isValid()) {
                // Process form data
                return $this->redirectToRoute('success');
            }
            
            return $this->render('contact/form.html.twig', [
                'form' => $form->createView(),
            ]);
        }
    }
    
    return new FormController();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 5: Disabling CSRF protection in a form builder
function bad_case_5() {
    use Symfony\Component\Form\FormBuilderInterface;
    use Symfony\Component\Form\Extension\Core\Type\TextType;
    use Symfony\Component\Form\Extension\Core\Type\SubmitType;
    
    // ruleid: php-symfony-csrf-protection-disabled
    $formBuilder = new FormBuilderInterface('user_form', null, [
        'csrf_protection' => false,
    ]);
    
    $formBuilder->add('username', TextType::class)
               ->add('submit', SubmitType::class);
    
    return $formBuilder->getForm();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 6: Disabling CSRF protection in a form factory
function bad_case_6() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ruleid: php-symfony-csrf-protection-disabled
    $formBuilder = $formFactory->createBuilder(FormType::class, null, [
        'csrf_protection' => false,
    ]);
    
    return $formBuilder->getForm();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 7: Disabling CSRF protection in a service configuration
function bad_case_7() {
    // ruleid: php-symfony-csrf-protection-disabled
    $container->loadFromExtension('framework', [
        'csrf_protection' => false,
    ]);
    
    return $container;
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 8: Disabling CSRF protection in a form extension
function bad_case_8() {
    use Symfony\Component\Form\AbstractTypeExtension;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    use Symfony\Component\OptionsResolver\OptionsResolver;
    
    class DisableCsrfExtension extends AbstractTypeExtension {
        public function configureOptions(OptionsResolver $resolver) {
            // ruleid: php-symfony-csrf-protection-disabled
            $resolver->setDefaults([
                'csrf_protection' => false,
            ]);
        }
        
        public static function getExtendedTypes(): iterable {
            return [FormType::class];
        }
    }
    
    return new DisableCsrfExtension();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 9: Disabling CSRF protection in a form collection
function bad_case_9() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\CollectionType;
    use Symfony\Component\Form\Extension\Core\Type\TextType;
    
    $formFactory = new FormFactoryInterface();
    
    // ruleid: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(CollectionType::class, null, [
        'entry_type' => TextType::class,
        'csrf_protection' => false,
    ]);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 10: Disabling CSRF protection in a form with multiple options
function bad_case_10() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ruleid: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(FormType::class, null, [
        'data_class' => 'App\Entity\User',
        'method' => 'POST',
        'csrf_protection' => false,
        'attr' => ['class' => 'form-horizontal'],
    ]);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 11: Disabling CSRF protection in a form with conditional logic
function bad_case_11() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    $isAdminUser = true;
    $options = [
        'data_class' => 'App\Entity\Product',
    ];
    
    if ($isAdminUser) {
        // ruleid: php-symfony-csrf-protection-disabled
        $options['csrf_protection'] = false;
    }
    
    $form = $formFactory->create(FormType::class, null, $options);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 12: Disabling CSRF protection in a form with environment check
function bad_case_12() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    $env = 'dev';
    
    $options = [];
    if ($env === 'dev') {
        // ruleid: php-symfony-csrf-protection-disabled
        $options['csrf_protection'] = false;
    }
    
    $form = $formFactory->create(FormType::class, null, $options);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 13: Disabling CSRF protection in a form with API check
function bad_case_13() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    use Symfony\Component\HttpFoundation\Request;
    
    $formFactory = new FormFactoryInterface();
    $request = new Request();
    $isApiRequest = strpos($request->getPathInfo(), '/api/') === 0;
    
    $options = [];
    if ($isApiRequest) {
        // ruleid: php-symfony-csrf-protection-disabled
        $options['csrf_protection'] = false;
    }
    
    $form = $formFactory->create(FormType::class, null, $options);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 14: Disabling CSRF protection in config with variable
function bad_case_14() {
    $enableCsrf = false;
    
    // ruleid: php-symfony-csrf-protection-disabled
    $config = [
        'framework' => [
            'csrf_protection' => $enableCsrf,
        ]
    ];
    
    $container = new Symfony\Component\DependencyInjection\ContainerBuilder();
    $loader = new Symfony\Component\DependencyInjection\Loader\YamlFileLoader($container);
    $loader->load($config);
    
    return $container;
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// Example 15: Disabling CSRF protection with string value
function bad_case_15() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ruleid: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(FormType::class, null, [
        'csrf_protection' => 'false', // String "false" will be converted to boolean false
    ]);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// True Negative Examples (Secure Code)

// Example 1: Enabling CSRF protection in Symfony config.yml
function good_case_1() {
    // ok: php-symfony-csrf-protection-disabled
    $config = [
        'framework' => [
            'csrf_protection' => true,
        ]
    ];
    
    $container = new Symfony\Component\DependencyInjection\ContainerBuilder();
    $loader = new Symfony\Component\DependencyInjection\Loader\YamlFileLoader($container);
    $loader->load($config);
    
    return $container;
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 2: Using default CSRF protection in a Symfony form (enabled by default)
function good_case_2() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ok: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(FormType::class);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 3: Explicitly enabling CSRF protection in a custom form type
function good_case_3() {
    use Symfony\Component\Form\AbstractType;
    use Symfony\Component\Form\FormBuilderInterface;
    use Symfony\Component\OptionsResolver\OptionsResolver;
    
    class ContactFormType extends AbstractType {
        public function buildForm(FormBuilderInterface $builder, array $options) {
            $builder
                ->add('name', TextType::class)
                ->add('email', EmailType::class)
                ->add('submit', SubmitType::class);
        }
        
        public function configureOptions(OptionsResolver $resolver) {
            // ok: php-symfony-csrf-protection-disabled
            $resolver->setDefaults([
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id'   => 'contact_form',
            ]);
        }
    }
    
    return new ContactFormType();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 4: Enabling CSRF protection in a controller
function good_case_4() {
    use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
    use Symfony\Component\HttpFoundation\Request;
    use Symfony\Component\HttpFoundation\Response;
    
    class FormController extends AbstractController {
        public function contactAction(Request $request): Response {
            // ok: php-symfony-csrf-protection-disabled
            $form = $this->createForm(ContactType::class, null, [
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
            ]);
            
            $form->handleRequest($request);
            
            if ($form->isSubmitted() && $form->isValid()) {
                // Process form data
                return $this->redirectToRoute('success');
            }
            
            return $this->render('contact/form.html.twig', [
                'form' => $form->createView(),
            ]);
        }
    }
    
    return new FormController();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 5: Using default CSRF protection in a form builder (enabled by default)
function good_case_5() {
    use Symfony\Component\Form\FormBuilderInterface;
    use Symfony\Component\Form\Extension\Core\Type\TextType;
    use Symfony\Component\Form\Extension\Core\Type\SubmitType;
    
    // ok: php-symfony-csrf-protection-disabled
    $formBuilder = new FormBuilderInterface('user_form');
    
    $formBuilder->add('username', TextType::class)
               ->add('submit', SubmitType::class);
    
    return $formBuilder->getForm();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 6: Explicitly enabling CSRF protection in a form factory
function good_case_6() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ok: php-symfony-csrf-protection-disabled
    $formBuilder = $formFactory->createBuilder(FormType::class, null, [
        'csrf_protection' => true,
        'csrf_field_name' => '_token',
        'csrf_token_id'   => 'user_form',
    ]);
    
    return $formBuilder->getForm();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 7: Enabling CSRF protection in a service configuration
function good_case_7() {
    // ok: php-symfony-csrf-protection-disabled
    $container->loadFromExtension('framework', [
        'csrf_protection' => true,
    ]);
    
    return $container;
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 8: Enabling CSRF protection in a form extension
function good_case_8() {
    use Symfony\Component\Form\AbstractTypeExtension;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    use Symfony\Component\OptionsResolver\OptionsResolver;
    
    class EnhanceCsrfExtension extends AbstractTypeExtension {
        public function configureOptions(OptionsResolver $resolver) {
            // ok: php-symfony-csrf-protection-disabled
            $resolver->setDefaults([
                'csrf_protection' => true,
                'csrf_field_name' => '_token',
                'csrf_token_id'   => 'enhanced_form',
            ]);
        }
        
        public static function getExtendedTypes(): iterable {
            return [FormType::class];
        }
    }
    
    return new EnhanceCsrfExtension();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 9: Enabling CSRF protection in a form collection
function good_case_9() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\CollectionType;
    use Symfony\Component\Form\Extension\Core\Type\TextType;
    
    $formFactory = new FormFactoryInterface();
    
    // ok: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(CollectionType::class, null, [
        'entry_type' => TextType::class,
        'csrf_protection' => true,
    ]);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 10: Enabling CSRF protection in a form with multiple options
function good_case_10() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ok: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(FormType::class, null, [
        'data_class' => 'App\Entity\User',
        'method' => 'POST',
        'csrf_protection' => true,
        'attr' => ['class' => 'form-horizontal'],
    ]);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 11: Enabling CSRF protection with conditional logic
function good_case_11() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    $isAdminUser = true;
    $options = [
        'data_class' => 'App\Entity\Product',
    ];
    
    if ($isAdminUser) {
        // ok: php-symfony-csrf-protection-disabled
        $options['csrf_protection'] = true;
        $options['csrf_field_name'] = '_admin_token';
    }
    
    $form = $formFactory->create(FormType::class, null, $options);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 12: Enabling CSRF protection with environment check
function good_case_12() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    $env = 'prod';
    
    $options = [];
    // ok: php-symfony-csrf-protection-disabled
    if ($env === 'prod') {
        $options['csrf_protection'] = true;
        $options['csrf_field_name'] = '_token';
    } else {
        $options['csrf_protection'] = true; // Still enabled in dev
    }
    
    $form = $formFactory->create(FormType::class, null, $options);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 13: Enabling CSRF protection for API requests
function good_case_13() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    use Symfony\Component\HttpFoundation\Request;
    
    $formFactory = new FormFactoryInterface();
    $request = new Request();
    $isApiRequest = strpos($request->getPathInfo(), '/api/') === 0;
    
    $options = [];
    // ok: php-symfony-csrf-protection-disabled
    if ($isApiRequest) {
        $options['csrf_protection'] = true;
        $options['csrf_field_name'] = '_api_token';
    } else {
        $options['csrf_protection'] = true;
    }
    
    $form = $formFactory->create(FormType::class, null, $options);
    
    return $form->createView();
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 14: Enabling CSRF protection in config with variable
function good_case_14() {
    $enableCsrf = true;
    
    // ok: php-symfony-csrf-protection-disabled
    $config = [
        'framework' => [
            'csrf_protection' => $enableCsrf,
        ]
    ];
    
    $container = new Symfony\Component\DependencyInjection\ContainerBuilder();
    $loader = new Symfony\Component\DependencyInjection\Loader\YamlFileLoader($container);
    $loader->load($config);
    
    return $container;
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// Example 15: Not specifying CSRF protection (defaults to enabled)
function good_case_15() {
    use Symfony\Component\Form\FormFactoryInterface;
    use Symfony\Component\Form\Extension\Core\Type\FormType;
    
    $formFactory = new FormFactoryInterface();
    
    // ok: php-symfony-csrf-protection-disabled
    $form = $formFactory->create(FormType::class, null, [
        'data_class' => 'App\Entity\User',
        'method' => 'POST',
        // CSRF protection is enabled by default
    ]);
    
    return $form->createView();
}
// {/fact}
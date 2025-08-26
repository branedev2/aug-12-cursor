<?php

/**
 * True Positive Examples (Vulnerable Code)
 */
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 1: Direct instantiation with GET parameter
function bad_case_1() {
    $className = $_GET['class'];
    // ruleid: php-tainted-object-instantiation
    $object = new $className();
    $object->doSomething();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 2: POST data used for class instantiation
function bad_case_2() {
    $userData = $_POST['user_type'];
    // Some basic processing that doesn't sanitize the class name
    $className = trim($userData);
    // ruleid: php-tainted-object-instantiation
    $instance = new $className();
    return $instance->getData();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 3: Using REQUEST with string concatenation
function bad_case_3() {
    $type = $_REQUEST['type'];
    $namespace = "App\\Models\\";
    // Concatenation doesn't make it safe
    $fullClassName = $namespace . $type;
    // ruleid: php-tainted-object-instantiation
    $model = new $fullClassName();
    $model->process();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 4: Using a header value for class instantiation
function bad_case_4() {
    $headers = getallheaders();
    $classType = $headers['X-Class-Type'];
    // ruleid: php-tainted-object-instantiation
    $handler = new $classType();
    $handler->handleRequest();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 5: Using cookie data for instantiation
function bad_case_5() {
    $preferredClass = $_COOKIE['preferred_renderer'];
    // ruleid: php-tainted-object-instantiation
    $renderer = new $preferredClass();
    $renderer->render();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 6: JSON input from POST request
function bad_case_6() {
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $className = $jsonData['handler_class'];
    // ruleid: php-tainted-object-instantiation
    $handler = new $className();
    $handler->process();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 7: Using URL path segments
function bad_case_7() {
    $uri = $_SERVER['REQUEST_URI'];
    $segments = explode('/', trim($uri, '/'));
    $className = ucfirst(end($segments)) . 'Controller';
    // ruleid: php-tainted-object-instantiation
    $controller = new $className();
    $controller->index();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 8: Class name from query string with constructor arguments
function bad_case_8() {
    $type = $_GET['widget_type'];
    $config = ['color' => 'blue', 'size' => 'large'];
    // ruleid: php-tainted-object-instantiation
    $widget = new $type($config);
    $widget->display();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 9: Using a factory pattern but with tainted input
function bad_case_9() {
    $format = $_GET['format'];
    $formatterClass = $format . 'Formatter';
    // ruleid: php-tainted-object-instantiation
    $formatter = new $formatterClass();
    return $formatter->format($data);
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 10: Multiple variable transformations but still tainted
function bad_case_10() {
    $input = $_POST['component'];
    $cleaned = preg_replace('/[^a-zA-Z0-9_]/', '', $input);
    $capitalized = ucfirst($cleaned);
    $className = $capitalized . 'Component';
    // ruleid: php-tainted-object-instantiation
    $component = new $className();
    $component->initialize();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 11: Using tainted data with namespace and reflection
function bad_case_11() {
    $type = $_GET['entity_type'];
    $namespace = "App\\Entities\\";
    $fullClassName = $namespace . $type;
    // ruleid: php-tainted-object-instantiation
    $entity = new $fullClassName();
    $entity->save();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 12: Tainted class name in a switch statement
function bad_case_12() {
    $handler = $_POST['handler'];
    $className = '';
    
    switch(strtolower($handler)) {
        case 'json':
            $className = 'JsonHandler';
            break;
        case 'xml':
            $className = 'XmlHandler';
            break;
        default:
            $className = $handler . 'Handler'; // Still tainted
    }
    
    // ruleid: php-tainted-object-instantiation
    $processor = new $className();
    $processor->process();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 13: Using tainted input with dynamic class loading
function bad_case_13() {
    $module = $_GET['module'];
    $className = 'Module_' . $module;
    
    if (class_exists($className)) {
        // ruleid: php-tainted-object-instantiation
        $moduleInstance = new $className();
        $moduleInstance->run();
    }
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 14: Using tainted input with constructor arguments array
function bad_case_14() {
    $strategy = $_POST['strategy'];
    $args = [
        'timeout' => 30,
        'retries' => 3
    ];
    
    // ruleid: php-tainted-object-instantiation
    $handler = new $strategy($args);
    $handler->execute();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=1}

// Example 15: Using tainted input from environment variables (still external input)
function bad_case_15() {
    // Environment variables can be set by users in some contexts
    $pluginType = $_ENV['PLUGIN_TYPE'];
    $pluginClass = $pluginType . 'Plugin';
    
    // ruleid: php-tainted-object-instantiation
    $plugin = new $pluginClass();
    $plugin->register();
}
// {/fact}

/**
 * True Negative Examples (Secure Code)
 */
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 1: Using a whitelist of allowed classes
function good_case_1() {
    $requestedClass = $_GET['class'];
    $allowedClasses = ['UserModel', 'ProductModel', 'OrderModel'];
    
    if (in_array($requestedClass, $allowedClasses)) {
        // ok: php-tainted-object-instantiation
        $object = new $requestedClass();
        $object->doSomething();
    } else {
        throw new Exception("Invalid class requested");
    }
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 2: Using a switch statement with fixed class names
function good_case_2() {
    $type = $_POST['type'];
    $className = '';
    
    switch ($type) {
        case 'user':
            $className = 'UserHandler';
            break;
        case 'product':
            $className = 'ProductHandler';
            break;
        default:
            $className = 'DefaultHandler';
    }
    
    // ok: php-tainted-object-instantiation
    $handler = new $className();
    return $handler->process();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 3: Using a mapping array for class selection
function good_case_3() {
    $format = $_REQUEST['format'];
    
    $formatters = [
        'json' => 'JsonFormatter',
        'xml' => 'XmlFormatter',
        'csv' => 'CsvFormatter',
    ];
    
    $formatterClass = $formatters[$format] ?? 'DefaultFormatter';
    
    // ok: php-tainted-object-instantiation
    $formatter = new $formatterClass();
    return $formatter->format();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 4: Factory method with strict validation
function good_case_4() {
    $type = $_GET['widget_type'];
    
    // Strict validation against allowed types
    if (!preg_match('/^[a-zA-Z]+$/', $type)) {
        throw new Exception("Invalid widget type");
    }
    
    $widgetClass = null;
    if ($type === 'basic') {
        $widgetClass = 'BasicWidget';
    } elseif ($type === 'advanced') {
        $widgetClass = 'AdvancedWidget';
    } else {
        $widgetClass = 'DefaultWidget';
    }
    
    // ok: php-tainted-object-instantiation
    $widget = new $widgetClass();
    return $widget->render();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 5: Using class_exists with a whitelist
function good_case_5() {
    $className = $_POST['handler'];
    $allowedNamespace = 'App\\SafeHandlers\\';
    $allowedHandlers = ['JsonHandler', 'XmlHandler', 'CsvHandler'];
    
    if (in_array($className, $allowedHandlers) && class_exists($allowedNamespace . $className)) {
        $fullClassName = $allowedNamespace . $className;
        // ok: php-tainted-object-instantiation
        $handler = new $fullClassName();
        $handler->process();
    }
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 6: Using hardcoded class names
function good_case_6() {
    $action = $_GET['action'];
    
    $className = 'DefaultController';
    if ($action === 'list') {
        $className = 'ListController';
    } elseif ($action === 'edit') {
        $className = 'EditController';
    }
    
    // ok: php-tainted-object-instantiation
    $controller = new $className();
    $controller->execute();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 7: Using a constant array for mapping
function good_case_7() {
    $type = $_REQUEST['entity_type'];
    
    const ENTITY_MAP = [
        'user' => 'UserEntity',
        'product' => 'ProductEntity',
        'order' => 'OrderEntity'
    ];
    
    $entityClass = ENTITY_MAP[$type] ?? 'DefaultEntity';
    
    // ok: php-tainted-object-instantiation
    $entity = new $entityClass();
    $entity->load();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 8: Using a method to get the class name
function good_case_8() {
    $format = $_GET['format'];
    $className = getFormatterClass($format);
    
    // ok: php-tainted-object-instantiation
    $formatter = new $className();
    return $formatter->format();
}
// {/fact}

function getFormatterClass($format) {
    $map = [
        'json' => 'JsonFormatter',
        'xml' => 'XmlFormatter',
        'yaml' => 'YamlFormatter'
    ];
    
    return $map[$format] ?? 'DefaultFormatter';
}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 9: Using a configuration array
function good_case_9() {
    $moduleType = $_POST['module'];
    
    $config = [
        'auth' => 'AuthModule',
        'user' => 'UserModule',
        'admin' => 'AdminModule',
        'report' => 'ReportModule'
    ];
    
    $moduleClass = array_key_exists($moduleType, $config) ? $config[$moduleType] : 'DefaultModule';
    
    // ok: php-tainted-object-instantiation
    $module = new $moduleClass();
    $module->initialize();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 10: Using a validation function
function good_case_10() {
    $type = $_GET['handler_type'];
    
    if (!isValidHandlerType($type)) {
        throw new Exception("Invalid handler type");
    }
    
    $handlerClass = getHandlerClass($type);
    
    // ok: php-tainted-object-instantiation
    $handler = new $handlerClass();
    $handler->handle();
}
// {/fact}

function isValidHandlerType($type) {
    return in_array($type, ['basic', 'advanced', 'premium']);
}

function getHandlerClass($type) {
    $classes = [
        'basic' => 'BasicHandler',
        'advanced' => 'AdvancedHandler',
        'premium' => 'PremiumHandler'
    ];
    
    return $classes[$type];
}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 11: Using class constants
function good_case_11() {
    $viewType = $_REQUEST['view'];
    
    class ViewFactory {
        const JSON_VIEW = 'JsonView';
        const HTML_VIEW = 'HtmlView';
        const PDF_VIEW = 'PdfView';
        
        public static function getViewClass($type) {
            switch ($type) {
                case 'json': return self::JSON_VIEW;
                case 'html': return self::HTML_VIEW;
                case 'pdf': return self::PDF_VIEW;
                default: return 'DefaultView';
            }
        }
    }
    
    $viewClass = ViewFactory::getViewClass($viewType);
    
    // ok: php-tainted-object-instantiation
    $view = new $viewClass();
    $view->render();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 12: Using a registry pattern
function good_case_12() {
    $componentName = $_GET['component'];
    
    class ComponentRegistry {
        private static $components = [
            'logger' => 'LoggerComponent',
            'cache' => 'CacheComponent',
            'database' => 'DatabaseComponent'
        ];
        
        public static function getComponent($name) {
            return isset(self::$components[$name]) ? self::$components[$name] : 'DefaultComponent';
        }
    }
    
    $componentClass = ComponentRegistry::getComponent($componentName);
    
    // ok: php-tainted-object-instantiation
    $component = new $componentClass();
    $component->initialize();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 13: Using a factory class with validation
function good_case_13() {
    $strategyName = $_POST['strategy'];
    
    class StrategyFactory {
        private static $strategies = ['simple', 'complex', 'hybrid'];
        
        public static function createStrategy($name) {
            if (!in_array($name, self::$strategies)) {
                return new DefaultStrategy();
            }
            
            $className = ucfirst($name) . 'Strategy';
            return new $className();
        }
    }
    
    // ok: php-tainted-object-instantiation
    $strategy = StrategyFactory::createStrategy($strategyName);
    $strategy->execute();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 14: Using reflection with validation
function good_case_14() {
    $adapterName = $_GET['adapter'];
    
    $allowedAdapters = [
        'mysql' => 'MysqlAdapter',
        'postgres' => 'PostgresAdapter',
        'sqlite' => 'SqliteAdapter'
    ];
    
    if (!array_key_exists($adapterName, $allowedAdapters)) {
        throw new Exception("Invalid adapter requested");
    }
    
    $adapterClass = $allowedAdapters[$adapterName];
    
    // ok: php-tainted-object-instantiation
    $adapter = new $adapterClass();
    $adapter->connect();
}
// {/fact}
// {fact rule=unsafe-reflection@v1.0 defects=0}

// Example 15: Using a service container
function good_case_15() {
    $serviceName = $_REQUEST['service'];
    
    class ServiceContainer {
        private $services = [
            'mail' => 'MailService',
            'notification' => 'NotificationService',
            'payment' => 'PaymentService'
        ];
        
        public function get($name) {
            if (!isset($this->services[$name])) {
                throw new Exception("Service not found");
            }
            
            $className = $this->services[$name];
            return new $className();
        }
    }
    
    $container = new ServiceContainer();
    
    try {
        // ok: php-tainted-object-instantiation
        $service = $container->get($serviceName);
        $service->execute();
    } catch (Exception $e) {
        // Handle service not found
    }
}
// {/fact}
?>
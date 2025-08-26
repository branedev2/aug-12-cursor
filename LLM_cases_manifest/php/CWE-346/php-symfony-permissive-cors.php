<?php
// Examples for php-symfony-permissive-cors rule
// This rule detects permissive CORS headers in Symfony applications

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;
use Nelmio\CorsBundle\EventListener\CorsListener;

class CorsExamplesController extends AbstractController
{
    /**
     * Vulnerable example 1: Setting wildcard CORS header directly
     */
    public function bad_case_1(Request $request): Response
    {
        $response = new Response('API data');
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        
        return $response;
    }

    /**
     * Vulnerable example 2: Setting wildcard CORS in JSON response
     */
    public function bad_case_2(Request $request): JsonResponse
    {
        $data = ['status' => 'success', 'data' => 'Sensitive information'];
        $response = new JsonResponse($data);
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Credentials', 'true');
        
        return $response;
    }

    /**
     * Vulnerable example 3: Setting wildcard CORS in API controller
     * 
     * @Route("/api/users", name="api_users", methods={"GET"})
     */
    public function bad_case_3(): Response
    {
        $users = ['user1', 'user2', 'user3'];
        $response = $this->json($users);
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Methods', 'GET');
        
        return $response;
    }

    /**
     * Vulnerable example 4: Setting wildcard CORS in error handler
     */
    public function bad_case_4(Request $request): Response
    {
        try {
            // Some code that might throw an exception
            throw new \Exception('Something went wrong');
        } catch (\Exception $e) {
            $response = new Response('Error: ' . $e->getMessage(), 500);
            // ruleid: php-symfony-permissive-cors
            $response->headers->set('Access-Control-Allow-Origin', '*');
            return $response;
        }
    }

    /**
     * Vulnerable example 5: Setting wildcard CORS with conditional logic
     */
    public function bad_case_5(Request $request): Response
    {
        $response = new Response('API data');
        
        if ($request->isMethod('OPTIONS')) {
            // ruleid: php-symfony-permissive-cors
            $response->headers->set('Access-Control-Allow-Origin', '*');
            $response->headers->set('Access-Control-Allow-Methods', 'GET, POST');
            $response->headers->set('Access-Control-Allow-Headers', 'Content-Type');
        }
        
        return $response;
    }

    /**
     * Vulnerable example 6: Setting wildcard CORS in a service response
     */
    public function bad_case_6(Request $request): Response
    {
        $data = $this->fetchDataFromService();
        $response = new Response($data);
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Max-Age', '3600');
        
        return $response;
    }

    /**
     * Vulnerable example 7: Setting wildcard CORS in file download
     */
    public function bad_case_7(Request $request): Response
    {
        $filePath = '/path/to/file.pdf';
        $response = new Response(file_get_contents($filePath));
        $response->headers->set('Content-Type', 'application/pdf');
        $response->headers->set('Content-Disposition', 'attachment; filename="document.pdf"');
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        
        return $response;
    }

    /**
     * Vulnerable example 8: Setting wildcard CORS with dynamic content type
     */
    public function bad_case_8(Request $request): Response
    {
        $contentType = $request->query->get('format', 'json');
        $data = ['result' => 'success'];
        
        if ($contentType === 'xml') {
            $content = $this->convertToXml($data);
            $response = new Response($content);
            $response->headers->set('Content-Type', 'application/xml');
        } else {
            $content = json_encode($data);
            $response = new Response($content);
            $response->headers->set('Content-Type', 'application/json');
        }
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        
        return $response;
    }

    /**
     * Vulnerable example 9: Setting wildcard CORS in authentication endpoint
     */
    public function bad_case_9(Request $request): JsonResponse
    {
        $username = $request->request->get('username');
        $password = $request->request->get('password');
        
        // Authentication logic here
        $token = $this->generateAuthToken($username);
        
        $response = new JsonResponse(['token' => $token]);
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        
        return $response;
    }

    /**
     * Vulnerable example 10: Setting wildcard CORS with multiple headers
     */
    public function bad_case_10(Request $request): Response
    {
        $response = new Response('API data');
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
        $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
        $response->headers->set('Access-Control-Allow-Credentials', 'true');
        $response->headers->set('Access-Control-Max-Age', '86400');
        
        return $response;
    }

    /**
     * Vulnerable example 11: Setting wildcard CORS in a webhook handler
     */
    public function bad_case_11(Request $request): Response
    {
        $payload = json_decode($request->getContent(), true);
        
        // Process webhook data
        $this->processWebhookData($payload);
        
        $response = new Response('Webhook received');
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        
        return $response;
    }

    /**
     * Vulnerable example 12: Setting wildcard CORS with string concatenation
     */
    public function bad_case_12(Request $request): Response
    {
        $response = new Response('API data');
        $corsHeader = '*';
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', $corsHeader);
        
        return $response;
    }

    /**
     * Vulnerable example 13: Setting wildcard CORS with variable
     */
    public function bad_case_13(Request $request): Response
    {
        $response = new Response('API data');
        $allowOrigin = '*';
        
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', $allowOrigin);
        
        return $response;
    }

    /**
     * Vulnerable example 14: Setting wildcard CORS in a configuration method
     */
    public function bad_case_14(Request $request): Response
    {
        $response = new Response('API data');
        $this->configureCorsHeaders($response);
        
        return $response;
    }
    
    private function configureCorsHeaders(Response $response): void
    {
        // ruleid: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST');
    }

    /**
     * Vulnerable example 15: Setting wildcard CORS with environment check
     */
    public function bad_case_15(Request $request): Response
    {
        $response = new Response('API data');
        $env = $_ENV['APP_ENV'] ?? 'dev';
        
        if ($env === 'dev') {
            // ruleid: php-symfony-permissive-cors
            $response->headers->set('Access-Control-Allow-Origin', '*');
        } else {
            $response->headers->set('Access-Control-Allow-Origin', 'https://example.com');
        }
        
        return $response;
    }

    /**
     * Secure example 1: Setting specific origin
     */
    public function good_case_1(Request $request): Response
    {
        $response = new Response('API data');
        
        // ok: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', 'https://example.com');
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST');
        
        return $response;
    }

    /**
     * Secure example 2: Dynamically setting origin based on allowed list
     */
    public function good_case_2(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        $allowedOrigins = ['https://example.com', 'https://subdomain.example.com'];
        
        // ok: php-symfony-permissive-cors
        if (in_array($origin, $allowedOrigins)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
        }
        
        return $response;
    }

    /**
     * Secure example 3: Using environment configuration for CORS
     */
    public function good_case_3(Request $request): Response
    {
        $response = new Response('API data');
        $allowedOrigin = $_ENV['CORS_ALLOWED_ORIGIN'] ?? 'https://example.com';
        
        // ok: php-symfony-permissive-cors
        $response->headers->set('Access-Control-Allow-Origin', $allowedOrigin);
        
        return $response;
    }

    /**
     * Secure example 4: Setting multiple specific origins
     */
    public function good_case_4(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        $allowedOrigins = [
            'https://example.com',
            'https://app.example.com',
            'https://admin.example.com'
        ];
        
        // ok: php-symfony-permissive-cors
        if (in_array($origin, $allowedOrigins)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    /**
     * Secure example 5: Using regex pattern matching for origins
     */
    public function good_case_5(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        $pattern = '/^https:\/\/.*\.example\.com$/';
        
        // ok: php-symfony-permissive-cors
        if ($origin && preg_match($pattern, $origin)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    /**
     * Secure example 6: No CORS headers set (default restrictive)
     */
    public function good_case_6(Request $request): Response
    {
        // ok: php-symfony-permissive-cors
        $response = new Response('API data');
        // No CORS headers set, browser will use same-origin policy
        
        return $response;
    }

    /**
     * Secure example 7: Using a service to manage CORS
     */
    public function good_case_7(Request $request): Response
    {
        $response = new Response('API data');
        $corsService = new CorsService(['https://example.com', 'https://app.example.com']);
        
        // ok: php-symfony-permissive-cors
        $corsService->addCorsHeaders($request, $response);
        
        return $response;
    }

    /**
     * Secure example 8: Setting CORS with subdomain validation
     */
    public function good_case_8(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        
        // ok: php-symfony-permissive-cors
        if ($origin) {
            $host = parse_url($origin, PHP_URL_HOST);
            if ($host && (
                $host === 'example.com' || 
                substr($host, -11) === '.example.com'
            )) {
                $response->headers->set('Access-Control-Allow-Origin', $origin);
                $response->headers->set('Vary', 'Origin');
            }
        }
        
        return $response;
    }

    /**
     * Secure example 9: Using configuration from database
     */
    public function good_case_9(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        
        // Fetch allowed origins from database (simulated here)
        $allowedOrigins = $this->getDatabaseAllowedOrigins();
        
        // ok: php-symfony-permissive-cors
        if (in_array($origin, $allowedOrigins)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    /**
     * Secure example 10: Using a whitelist with domain validation
     */
    public function good_case_10(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        
        // ok: php-symfony-permissive-cors
        if ($origin && $this->isValidOrigin($origin)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    /**
     * Secure example 11: Using environment-specific CORS configuration
     */
    public function good_case_11(Request $request): Response
    {
        $response = new Response('API data');
        $env = $_ENV['APP_ENV'] ?? 'prod';
        
        if ($env === 'dev') {
            $allowedOrigins = ['https://localhost:8080', 'https://dev.example.com'];
        } else {
            $allowedOrigins = ['https://example.com', 'https://app.example.com'];
        }
        
        $origin = $request->headers->get('Origin');
        
        // ok: php-symfony-permissive-cors
        if (in_array($origin, $allowedOrigins)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    /**
     * Secure example 12: Using a CORS middleware
     */
    public function good_case_12(Request $request): Response
    {
        $response = new Response('API data');
        
        // CORS is handled by middleware, not in the controller
        // ok: php-symfony-permissive-cors
        
        return $response;
    }

    /**
     * Secure example 13: Using Nelmio CORS bundle configuration
     */
    public function good_case_13(Request $request): Response
    {
        // Using Nelmio CORS bundle with proper configuration in config/packages/nelmio_cors.yaml
        // ok: php-symfony-permissive-cors
        $response = new Response('API data');
        
        return $response;
    }

    /**
     * Secure example 14: Setting CORS with domain validation and TLS requirement
     */
    public function good_case_14(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        
        // ok: php-symfony-permissive-cors
        if ($origin && $this->isSecureOrigin($origin)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    /**
     * Secure example 15: Using a token-based CORS validation
     */
    public function good_case_15(Request $request): Response
    {
        $response = new Response('API data');
        $origin = $request->headers->get('Origin');
        $token = $request->headers->get('X-CORS-Token');
        
        // ok: php-symfony-permissive-cors
        if ($origin && $token && $this->validateCorsToken($origin, $token)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }
        
        return $response;
    }

    // Helper methods
    private function fetchDataFromService(): string
    {
        return 'Data from service';
    }
    
    private function convertToXml(array $data): string
    {
        return '<response><result>success</result></response>';
    }
    
    private function generateAuthToken(string $username): string
    {
        return md5($username . time());
    }
    
    private function processWebhookData(array $data): void
    {
        // Process webhook data
    }
    
    private function getDatabaseAllowedOrigins(): array
    {
        // Simulate fetching from database
        return ['https://example.com', 'https://app.example.com'];
    }
    
    private function isValidOrigin(string $origin): bool
    {
        $allowedDomains = ['example.com', 'trusted-partner.com'];
        $host = parse_url($origin, PHP_URL_HOST);
        
        foreach ($allowedDomains as $domain) {
            if ($host === $domain || substr($host, -strlen($domain) - 1) === '.' . $domain) {
                return true;
            }
        }
        
        return false;
    }
    
    private function isSecureOrigin(string $origin): bool
    {
        // Check if origin uses HTTPS
        if (strpos($origin, 'https://') !== 0) {
            return false;
        }
        
        // Check if domain is allowed
        $host = parse_url($origin, PHP_URL_HOST);
        $allowedDomains = ['example.com', 'trusted-partner.com'];
        
        foreach ($allowedDomains as $domain) {
            if ($host === $domain || substr($host, -strlen($domain) - 1) === '.' . $domain) {
                return true;
            }
        }
        
        return false;
    }
    
    private function validateCorsToken(string $origin, string $token): bool
    {
        // Validate that the token is valid for the given origin
        $validTokens = [
            'https://example.com' => 'token123',
            'https://app.example.com' => 'token456'
        ];
        
        return isset($validTokens[$origin]) && $validTokens[$origin] === $token;
    }
}

class CorsService
{
    private $allowedOrigins;
    
    public function __construct(array $allowedOrigins)
    {
        $this->allowedOrigins = $allowedOrigins;
    }
    
    public function addCorsHeaders(Request $request, Response $response): void
    {
        $origin = $request->headers->get('Origin');
        
        if (in_array($origin, $this->allowedOrigins)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
            $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
            $response->headers->set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        }
    }
}
?>
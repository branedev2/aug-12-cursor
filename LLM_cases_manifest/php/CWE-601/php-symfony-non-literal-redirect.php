<?php
// Import necessary Symfony components
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
// {fact rule=cross-site-scripting@v1.0 defects=1}

class RedirectController extends AbstractController
{
    /**
     * Example 1: Directly using user input in redirect without validation
     */
    public function bad_case_1(Request $request)
    {
        $url = $request->query->get('url');
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 2: Using POST parameter for redirect without validation
     */
    public function bad_case_2(Request $request)
    {
        $url = $request->request->get('redirect_to');
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 3: Using header value for redirect without validation
     */
    public function bad_case_3(Request $request)
    {
        $url = $request->headers->get('X-Redirect-To');
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 4: Using cookie value for redirect without validation
     */
    public function bad_case_4(Request $request)
    {
        $url = $request->cookies->get('return_url');
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 5: Using request attribute for redirect without validation
     */
    public function bad_case_5(Request $request)
    {
        $url = $request->attributes->get('redirect_url');
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 6: Using concatenated user input in redirect without validation
     */
    public function bad_case_6(Request $request)
    {
        $path = $request->query->get('path');
        $url = 'https://' . $path;
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 7: Using variable with conditional assignment without validation
     */
    public function bad_case_7(Request $request)
    {
        $url = $request->query->has('url') ? $request->query->get('url') : '/default';
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 8: Using JSON data for redirect without validation
     */
    public function bad_case_8(Request $request)
    {
        $data = json_decode($request->getContent(), true);
        $url = $data['redirect_url'] ?? '/home';
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 9: Using multiple request parameters to build URL without validation
     */
    public function bad_case_9(Request $request)
    {
        $domain = $request->query->get('domain');
        $path = $request->query->get('path');
        $url = "https://{$domain}/{$path}";
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 10: Using URL from session without validation
     */
    public function bad_case_10(Request $request)
    {
        $session = $request->getSession();
        $url = $session->get('redirect_url');
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 11: Using URL from database without validation
     */
    public function bad_case_11(Request $request)
    {
        $id = $request->query->get('id');
        // Simulating database fetch
        $url = $this->getDoctrine()->getRepository('App:Redirect')->find($id)->getUrl();
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 12: Using URL with minimal processing without validation
     */
    public function bad_case_12(Request $request)
    {
        $url = trim($request->query->get('next'));
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 13: Using URL with string manipulation without validation
     */
    public function bad_case_13(Request $request)
    {
        $url = $request->query->get('url');
        $url = str_replace(' ', '+', $url);
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 14: Using URL with array access without validation
     */
    public function bad_case_14(Request $request)
    {
        $params = $request->query->all();
        $url = $params['redirect'] ?? '/home';
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 15: Using URL with ternary and null coalescing without validation
     */
    public function bad_case_15(Request $request)
    {
        $isAdmin = $request->query->get('admin') === 'true';
        $url = $isAdmin ? $request->query->get('admin_url') ?? '/admin' : $request->query->get('user_url') ?? '/user';
        
        // ruleid: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 1: Using a hardcoded URL for redirect
     */
    public function good_case_1(Request $request)
    {
        // ok: php-symfony-non-literal-redirect
        return $this->redirect('/dashboard');
    }

    /**
     * Example 2: Validating URL with filter_var before redirect
     */
    public function good_case_2(Request $request)
    {
        $url = $request->query->get('url');
        
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 3: Checking URL against whitelist before redirect
     */
    public function good_case_3(Request $request)
    {
        $url = $request->query->get('url');
        $allowedDomains = ['example.com', 'subdomain.example.com', 'otherdomain.org'];
        
        $parsedUrl = parse_url($url);
        $host = $parsedUrl['host'] ?? '';
        
        if (in_array($host, $allowedDomains)) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 4: Using a route name for redirect
     */
    public function good_case_4(Request $request)
    {
        // ok: php-symfony-non-literal-redirect
        return $this->redirectToRoute('app_homepage');
    }

    /**
     * Example 5: Using a route name with parameters for redirect
     */
    public function good_case_5(Request $request)
    {
        $id = $request->query->get('id');
        
        // ok: php-symfony-non-literal-redirect
        return $this->redirectToRoute('app_product_view', ['id' => $id]);
    }

    /**
     * Example 6: Validating URL with custom function before redirect
     */
    public function good_case_6(Request $request)
    {
        $url = $request->query->get('url');
        
        if ($this->isUrlSafe($url)) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }
    
    private function isUrlSafe($url)
    {
        // Check if URL is valid
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return false;
        }
        
        // Check if URL is in allowed domains
        $parsedUrl = parse_url($url);
        $allowedDomains = ['example.com', 'trusted-site.org'];
        
        return in_array($parsedUrl['host'] ?? '', $allowedDomains);
    }

    /**
     * Example 7: Using path-only redirect with validation
     */
    public function good_case_7(Request $request)
    {
        $path = $request->query->get('path');
        
        // Ensure it's just a path, not a full URL
        if (strpos($path, '://') === false && strpos($path, '//') === false && $path[0] === '/') {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($path);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 8: Using URL with domain validation and protocol enforcement
     */
    public function good_case_8(Request $request)
    {
        $url = $request->query->get('url');
        $parsedUrl = parse_url($url);
        
        if (isset($parsedUrl['host']) && $parsedUrl['host'] === 'example.com') {
            // Ensure HTTPS
            $secureUrl = 'https://example.com' . ($parsedUrl['path'] ?? '');
            
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($secureUrl);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 9: Using URL pattern matching for validation
     */
    public function good_case_9(Request $request)
    {
        $url = $request->query->get('url');
        
        // Only allow URLs matching specific pattern
        if (preg_match('/^https:\/\/example\.com\/[a-zA-Z0-9\/_-]+$/', $url)) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 10: Using a URL builder with validation
     */
    public function good_case_10(Request $request)
    {
        $page = $request->query->get('page');
        $allowedPages = ['about', 'contact', 'products', 'services'];
        
        if (in_array($page, $allowedPages)) {
            $url = "https://example.com/{$page}";
            
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 11: Using a switch statement for controlled redirects
     */
    public function good_case_11(Request $request)
    {
        $action = $request->query->get('action');
        
        switch ($action) {
            case 'dashboard':
                // ok: php-symfony-non-literal-redirect
                return $this->redirect('/dashboard');
            case 'profile':
                // ok: php-symfony-non-literal-redirect
                return $this->redirect('/user/profile');
            case 'settings':
                // ok: php-symfony-non-literal-redirect
                return $this->redirect('/user/settings');
            default:
                // ok: php-symfony-non-literal-redirect
                return $this->redirect('/home');
        }
    }

    /**
     * Example 12: Using a map for controlled redirects
     */
    public function good_case_12(Request $request)
    {
        $page = $request->query->get('page');
        
        $urlMap = [
            'home' => '/home',
            'about' => '/about-us',
            'contact' => '/contact-us',
            'products' => '/our-products',
        ];
        
        $url = $urlMap[$page] ?? '/home';
        
        // ok: php-symfony-non-literal-redirect
        return $this->redirect($url);
    }

    /**
     * Example 13: Using a database lookup with validation
     */
    public function good_case_13(Request $request)
    {
        $slug = $request->query->get('page');
        
        // Sanitize the slug
        $slug = preg_replace('/[^a-z0-9-]/', '', strtolower($slug));
        
        // Get the URL from database (simulated)
        $url = $this->getDoctrine()->getRepository('App:Page')->findOneBy(['slug' => $slug])->getUrl();
        
        // Validate the URL is internal
        if (strpos($url, '/') === 0) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }

    /**
     * Example 14: Using a URL builder with parameter validation
     */
    public function good_case_14(Request $request)
    {
        $productId = $request->query->get('product');
        
        // Ensure product ID is numeric
        if (is_numeric($productId)) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirectToRoute('app_product_view', ['id' => $productId]);
        }
        
        return $this->redirect('/products');
    }

    /**
     * Example 15: Using a signed URL for redirect
     */
    public function good_case_15(Request $request)
    {
        $url = $request->query->get('url');
        $signature = $request->query->get('signature');
        
        // Verify the signature (simplified example)
        $expectedSignature = hash_hmac('sha256', $url, $this->getParameter('app.secret'));
        
        if (hash_equals($expectedSignature, $signature)) {
            // ok: php-symfony-non-literal-redirect
            return $this->redirect($url);
        }
        
        return $this->redirect('/error');
    }
}
// {/fact}
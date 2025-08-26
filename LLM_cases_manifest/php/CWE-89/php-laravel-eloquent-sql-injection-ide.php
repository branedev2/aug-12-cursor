<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Models\User;
use App\Models\Product;
use App\Models\Order;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
// {fact rule=cross-site-scripting@v1.0 defects=1}

class ExampleController extends Controller
{
    // True Positive Examples (Vulnerable Code)

    public function bad_case_1(Request $request)
    {
        $column = $request->input('column');
        $value = $request->input('value');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $users = DB::table('users')
            ->whereRaw("$column = '$value'")
            ->get();
            
        return response()->json($users);
    }
    
    public function bad_case_2(Request $request)
    {
        $sortBy = $request->input('sort_by', 'id');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $products = DB::select("SELECT * FROM products ORDER BY $sortBy");
        
        return response()->json($products);
    }
    
    public function bad_case_3(Request $request)
    {
        $userId = $request->input('user_id');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $result = DB::table('users')
            ->select(DB::raw("name, email, (SELECT COUNT(*) FROM orders WHERE user_id = $userId) as order_count"))
            ->where('id', $userId)
            ->first();
            
        return response()->json($result);
    }
    
    public function bad_case_4(Request $request)
    {
        $tableName = $request->input('table');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $data = DB::table($tableName)->get();
        
        return response()->json($data);
    }
    
    public function bad_case_5(Request $request)
    {
        $searchTerm = $request->input('search');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $users = User::whereRaw("name LIKE '%$searchTerm%'")
            ->orWhereRaw("email LIKE '%$searchTerm%'")
            ->get();
            
        return response()->json($users);
    }
    
    public function bad_case_6(Request $request)
    {
        $columns = $request->input('columns', '*');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $users = DB::select("SELECT $columns FROM users");
        
        return response()->json($users);
    }
    
    public function bad_case_7(Request $request)
    {
        $joinCondition = $request->input('join_condition');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $results = DB::table('orders')
            ->join('users', DB::raw($joinCondition))
            ->select('orders.*', 'users.name')
            ->get();
            
        return response()->json($results);
    }
    
    public function bad_case_8(Request $request)
    {
        $groupBy = $request->input('group');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $results = DB::table('orders')
            ->select(DB::raw("COUNT(*) as count, $groupBy"))
            ->groupBy(DB::raw($groupBy))
            ->get();
            
        return response()->json($results);
    }
    
    public function bad_case_9(Request $request)
    {
        $havingClause = $request->input('having');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $results = DB::table('products')
            ->select('category', DB::raw('COUNT(*) as count'))
            ->groupBy('category')
            ->havingRaw($havingClause)
            ->get();
            
        return response()->json($results);
    }
    
    public function bad_case_10(Request $request)
    {
        $orderHeader = $request->header('X-Order-Column');
        $orderDirection = $request->header('X-Order-Direction', 'asc');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $users = User::orderByRaw("$orderHeader $orderDirection")->get();
        
        return response()->json($users);
    }
    
    public function bad_case_11(Request $request)
    {
        $userId = $request->cookie('user_id');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $user = DB::select("SELECT * FROM users WHERE id = $userId");
        
        return response()->json($user);
    }
    
    public function bad_case_12(Request $request)
    {
        $limit = $request->input('limit');
        $offset = $request->input('offset');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $products = DB::select("SELECT * FROM products LIMIT $limit OFFSET $offset");
        
        return response()->json($products);
    }
    
    public function bad_case_13(Request $request)
    {
        $whereClause = $request->input('where');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $orders = Order::whereRaw($whereClause)->get();
        
        return response()->json($orders);
    }
    
    public function bad_case_14(Request $request)
    {
        $jsonField = $request->input('json_field');
        $jsonValue = $request->input('json_value');
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $users = User::whereRaw("$jsonField->>'$.name' = '$jsonValue'")->get();
        
        return response()->json($users);
    }
    
    public function bad_case_15(Request $request)
    {
        $columns = implode(',', $request->input('columns', ['*']));
        
        // ruleid: php-laravel-eloquent-sql-injection-ide
        $results = DB::select("SELECT $columns FROM users");
        
        return response()->json($results);
    }
    
    // True Negative Examples (Safe Code)
    
    public function good_case_1(Request $request)
    {
        $column = $request->input('column');
        $value = $request->input('value');
        
        // Validate column name against allowed list
        $allowedColumns = ['name', 'email', 'created_at'];
        
        // ok: php-laravel-eloquent-sql-injection-ide
        if (!in_array($column, $allowedColumns)) {
            $column = 'id'; // Default to safe column
        }
        
        $users = DB::table('users')
            ->where($column, $value)
            ->get();
            
        return response()->json($users);
    }
    
    public function good_case_2(Request $request)
    {
        $sortBy = $request->input('sort_by', 'id');
        
        // Validate sort column
        $validator = Validator::make(['sort_by' => $sortBy], [
            'sort_by' => [
                'required',
                Rule::in(['id', 'name', 'price', 'created_at']),
            ],
        ]);
        
        if ($validator->fails()) {
            $sortBy = 'id'; // Default to safe column
        }
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $products = DB::table('products')
            ->orderBy($sortBy)
            ->get();
        
        return response()->json($products);
    }
    
    public function good_case_3(Request $request)
    {
        $userId = $request->input('user_id');
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $result = DB::table('users')
            ->select('name', 'email')
            ->addSelect(DB::raw('(SELECT COUNT(*) FROM orders WHERE user_id = ?) as order_count'))
            ->where('id', $userId)
            ->setBindings([$userId], 'select')
            ->first();
            
        return response()->json($result);
    }
    
    public function good_case_4(Request $request)
    {
        $tableName = $request->input('table');
        
        // Validate table name against allowed list
        $allowedTables = ['users', 'products', 'orders'];
        
        // ok: php-laravel-eloquent-sql-injection-ide
        if (in_array($tableName, $allowedTables)) {
            $data = DB::table($tableName)->get();
            return response()->json($data);
        }
        
        return response()->json(['error' => 'Invalid table name'], 400);
    }
    
    public function good_case_5(Request $request)
    {
        $searchTerm = $request->input('search');
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $users = User::where('name', 'LIKE', "%{$searchTerm}%")
            ->orWhere('email', 'LIKE', "%{$searchTerm}%")
            ->get();
            
        return response()->json($users);
    }
    
    public function good_case_6(Request $request)
    {
        $requestedColumns = $request->input('columns', ['*']);
        
        // Validate columns against allowed list
        $allowedColumns = ['id', 'name', 'email', 'created_at'];
        
        $columns = array_intersect($requestedColumns, $allowedColumns);
        
        if (empty($columns)) {
            $columns = ['id']; // Default to safe column
        }
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $users = DB::table('users')->select($columns)->get();
        
        return response()->json($users);
    }
    
    public function good_case_7(Request $request)
    {
        // ok: php-laravel-eloquent-sql-injection-ide
        $results = DB::table('orders')
            ->join('users', 'orders.user_id', '=', 'users.id')
            ->select('orders.*', 'users.name')
            ->get();
            
        return response()->json($results);
    }
    
    public function good_case_8(Request $request)
    {
        $groupBy = $request->input('group');
        
        // Validate group by column
        $allowedGroupColumns = ['status', 'category', 'date'];
        
        // ok: php-laravel-eloquent-sql-injection-ide
        if (in_array($groupBy, $allowedGroupColumns)) {
            $results = DB::table('orders')
                ->select($groupBy, DB::raw('COUNT(*) as count'))
                ->groupBy($groupBy)
                ->get();
                
            return response()->json($results);
        }
        
        return response()->json(['error' => 'Invalid grouping'], 400);
    }
    
    public function good_case_9(Request $request)
    {
        $minCount = (int) $request->input('min_count', 5);
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $results = DB::table('products')
            ->select('category', DB::raw('COUNT(*) as count'))
            ->groupBy('category')
            ->having('count', '>=', $minCount)
            ->get();
            
        return response()->json($results);
    }
    
    public function good_case_10(Request $request)
    {
        $orderHeader = $request->header('X-Order-Column', 'id');
        $orderDirection = $request->header('X-Order-Direction', 'asc');
        
        // Validate order column and direction
        $allowedColumns = ['id', 'name', 'created_at'];
        $allowedDirections = ['asc', 'desc'];
        
        // ok: php-laravel-eloquent-sql-injection-ide
        if (!in_array($orderHeader, $allowedColumns)) {
            $orderHeader = 'id';
        }
        
        if (!in_array(strtolower($orderDirection), $allowedDirections)) {
            $orderDirection = 'asc';
        }
        
        $users = User::orderBy($orderHeader, $orderDirection)->get();
        
        return response()->json($users);
    }
    
    public function good_case_11(Request $request)
    {
        $userId = $request->cookie('user_id');
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $user = DB::table('users')->where('id', $userId)->first();
        
        return response()->json($user);
    }
    
    public function good_case_12(Request $request)
    {
        $limit = (int) $request->input('limit', 10);
        $offset = (int) $request->input('offset', 0);
        
        // Ensure reasonable limits
        $limit = min(max($limit, 1), 100);
        $offset = max($offset, 0);
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $products = DB::table('products')
            ->limit($limit)
            ->offset($offset)
            ->get();
        
        return response()->json($products);
    }
    
    public function good_case_13(Request $request)
    {
        $status = $request->input('status');
        $minAmount = (float) $request->input('min_amount', 0);
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $query = Order::query();
        
        if ($status) {
            $query->where('status', $status);
        }
        
        if ($minAmount > 0) {
            $query->where('amount', '>=', $minAmount);
        }
        
        $orders = $query->get();
        
        return response()->json($orders);
    }
    
    public function good_case_14(Request $request)
    {
        $jsonValue = $request->input('json_value');
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $users = User::whereJsonContains('preferences->notifications', $jsonValue)->get();
        
        return response()->json($users);
    }
    
    public function good_case_15(Request $request)
    {
        $requestedColumns = $request->input('columns', ['*']);
        
        // Validate columns against allowed list
        $allowedColumns = ['id', 'name', 'email', 'created_at'];
        
        // ok: php-laravel-eloquent-sql-injection-ide
        $query = DB::table('users');
        
        if (is_array($requestedColumns)) {
            $validColumns = array_intersect($requestedColumns, $allowedColumns);
            if (!empty($validColumns)) {
                $query->select($validColumns);
            }
        }
        
        $results = $query->get();
        
        return response()->json($results);
    }
}
// {/fact}
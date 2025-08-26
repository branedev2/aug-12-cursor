<?php
// Laravel SQL Injection Test Cases

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Database\Eloquent\Builder;
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1(Request $request)
{
    $userId = $request->input('id');
    // ruleid: php-laravel-sql-injection
    $users = DB::select("SELECT * FROM users WHERE id = " . $userId);
    return response()->json($users);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2(Request $request)
{
    $searchTerm = $request->query('search');
    // ruleid: php-laravel-sql-injection
    $results = DB::select("SELECT * FROM products WHERE name LIKE '%" . $searchTerm . "%'");
    return view('products.index', ['products' => $results]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3(Request $request)
{
    $sortColumn = $request->input('sort', 'id');
    // ruleid: php-laravel-sql-injection
    $users = DB::select("SELECT * FROM users ORDER BY " . $sortColumn);
    return response()->json($users);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4(Request $request)
{
    $tableName = $request->input('table');
    // ruleid: php-laravel-sql-injection
    $results = DB::select("SELECT * FROM " . $tableName . " LIMIT 10");
    return view('data.index', ['data' => $results]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5(Request $request)
{
    $userId = $request->header('X-User-Id');
    // ruleid: php-laravel-sql-injection
    DB::statement("UPDATE users SET last_login = NOW() WHERE id = " . $userId);
    return response()->json(['status' => 'success']);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6(Request $request)
{
    $email = $request->cookie('user_email');
    // ruleid: php-laravel-sql-injection
    $user = DB::selectOne("SELECT * FROM users WHERE email = '" . $email . "'");
    return view('user.profile', ['user' => $user]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7(Request $request)
{
    $ids = $request->input('ids');
    // ruleid: php-laravel-sql-injection
    $products = DB::select("SELECT * FROM products WHERE id IN (" . $ids . ")");
    return response()->json($products);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8(Request $request)
{
    $category = $request->input('category');
    $minPrice = $request->input('min_price', 0);
    // ruleid: php-laravel-sql-injection
    $products = DB::select("SELECT * FROM products WHERE category = '" . $category . "' AND price > " . $minPrice);
    return view('products.category', ['products' => $products]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9(Request $request)
{
    $userId = $request->input('user_id');
    if ($userId) {
        // ruleid: php-laravel-sql-injection
        DB::unprepared("DELETE FROM user_sessions WHERE user_id = " . $userId);
    }
    return redirect('/');
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10(Request $request)
{
    $searchTerm = $request->input('search');
    $query = "SELECT * FROM products WHERE name LIKE '%" . $searchTerm . "%'";
    if ($request->has('category')) {
        $category = $request->input('category');
        $query .= " AND category = '" . $category . "'";
    }
    // ruleid: php-laravel-sql-injection
    $results = DB::select($query);
    return response()->json($results);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11(Request $request)
{
    $table = $request->input('table', 'users');
    $column = $request->input('column', 'id');
    $value = $request->input('value');
    // ruleid: php-laravel-sql-injection
    $result = DB::selectOne("SELECT * FROM " . $table . " WHERE " . $column . " = '" . $value . "'");
    return response()->json($result);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12(Request $request)
{
    $userId = $request->input('id');
    $fields = $request->input('fields', '*');
    // ruleid: php-laravel-sql-injection
    $user = DB::select("SELECT " . $fields . " FROM users WHERE id = " . $userId);
    return view('user.details', ['user' => $user]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13(Request $request)
{
    $orderBy = $request->input('order_by', 'created_at');
    $direction = $request->input('direction', 'DESC');
    // ruleid: php-laravel-sql-injection
    $posts = DB::select("SELECT * FROM posts ORDER BY " . $orderBy . " " . $direction);
    return response()->json($posts);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14(Request $request)
{
    $limit = $request->input('limit', 10);
    $offset = $request->input('offset', 0);
    // ruleid: php-laravel-sql-injection
    $users = DB::select("SELECT * FROM users LIMIT " . $limit . " OFFSET " . $offset);
    return view('users.index', ['users' => $users]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15(Request $request)
{
    $rawWhere = $request->input('filter');
    // ruleid: php-laravel-sql-injection
    $results = DB::select("SELECT * FROM products WHERE " . $rawWhere);
    return response()->json($results);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Safe Code)

function good_case_1(Request $request)
{
    $userId = $request->input('id');
    // ok: php-laravel-sql-injection
    $users = DB::select("SELECT * FROM users WHERE id = ?", [$userId]);
    return response()->json($users);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2(Request $request)
{
    $searchTerm = $request->query('search');
    // ok: php-laravel-sql-injection
    $results = DB::table('products')
        ->where('name', 'like', '%' . $searchTerm . '%')
        ->get();
    return view('products.index', ['products' => $results]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3(Request $request)
{
    $sortColumn = $request->input('sort', 'id');
    $allowedColumns = ['id', 'name', 'created_at', 'updated_at'];
    
    if (!in_array($sortColumn, $allowedColumns)) {
        $sortColumn = 'id';
    }
    
    // ok: php-laravel-sql-injection
    $users = DB::table('users')->orderBy($sortColumn)->get();
    return response()->json($users);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4(Request $request)
{
    $tableName = $request->input('table');
    $allowedTables = ['products', 'categories', 'tags'];
    
    if (!in_array($tableName, $allowedTables)) {
        return response()->json(['error' => 'Invalid table'], 400);
    }
    
    // ok: php-laravel-sql-injection
    $results = DB::table($tableName)->limit(10)->get();
    return view('data.index', ['data' => $results]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5(Request $request)
{
    $userId = $request->header('X-User-Id');
    // ok: php-laravel-sql-injection
    DB::table('users')
        ->where('id', $userId)
        ->update(['last_login' => DB::raw('NOW()')]);
    return response()->json(['status' => 'success']);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6(Request $request)
{
    $email = $request->cookie('user_email');
    // ok: php-laravel-sql-injection
    $user = DB::table('users')->where('email', $email)->first();
    return view('user.profile', ['user' => $user]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7(Request $request)
{
    $ids = $request->input('ids');
    $idArray = explode(',', $ids);
    // ok: php-laravel-sql-injection
    $products = DB::table('products')->whereIn('id', $idArray)->get();
    return response()->json($products);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8(Request $request)
{
    $category = $request->input('category');
    $minPrice = $request->input('min_price', 0);
    // ok: php-laravel-sql-injection
    $products = DB::table('products')
        ->where('category', $category)
        ->where('price', '>', $minPrice)
        ->get();
    return view('products.category', ['products' => $products]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9(Request $request)
{
    $userId = $request->input('user_id');
    if ($userId) {
        // ok: php-laravel-sql-injection
        DB::table('user_sessions')->where('user_id', $userId)->delete();
    }
    return redirect('/');
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10(Request $request)
{
    $searchTerm = $request->input('search');
    $query = DB::table('products')->where('name', 'like', '%' . $searchTerm . '%');
    
    if ($request->has('category')) {
        $category = $request->input('category');
        $query->where('category', $category);
    }
    
    // ok: php-laravel-sql-injection
    $results = $query->get();
    return response()->json($results);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11(Request $request)
{
    $table = $request->input('table', 'users');
    $column = $request->input('column', 'id');
    $value = $request->input('value');
    
    $allowedTables = ['users', 'profiles', 'settings'];
    $allowedColumns = ['id', 'name', 'email', 'status'];
    
    if (!in_array($table, $allowedTables) || !in_array($column, $allowedColumns)) {
        return response()->json(['error' => 'Invalid parameters'], 400);
    }
    
    // ok: php-laravel-sql-injection
    $result = DB::table($table)->where($column, $value)->first();
    return response()->json($result);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12(Request $request)
{
    $userId = $request->input('id');
    $fields = $request->input('fields', '*');
    
    $query = DB::table('users')->where('id', $userId);
    
    if ($fields !== '*') {
        $fieldArray = explode(',', $fields);
        $allowedFields = ['id', 'name', 'email', 'created_at'];
        $fieldArray = array_intersect($fieldArray, $allowedFields);
        $query->select($fieldArray);
    }
    
    // ok: php-laravel-sql-injection
    $user = $query->first();
    return view('user.details', ['user' => $user]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13(Request $request)
{
    $orderBy = $request->input('order_by', 'created_at');
    $direction = $request->input('direction', 'DESC');
    
    $allowedColumns = ['created_at', 'title', 'author', 'published_at'];
    $allowedDirections = ['ASC', 'DESC'];
    
    if (!in_array($orderBy, $allowedColumns)) {
        $orderBy = 'created_at';
    }
    
    if (!in_array(strtoupper($direction), $allowedDirections)) {
        $direction = 'DESC';
    }
    
    // ok: php-laravel-sql-injection
    $posts = DB::table('posts')->orderBy($orderBy, $direction)->get();
    return response()->json($posts);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14(Request $request)
{
    $limit = (int) $request->input('limit', 10);
    $offset = (int) $request->input('offset', 0);
    
    // Ensure reasonable limits
    if ($limit > 100) $limit = 100;
    if ($limit < 1) $limit = 10;
    if ($offset < 0) $offset = 0;
    
    // ok: php-laravel-sql-injection
    $users = DB::table('users')->skip($offset)->take($limit)->get();
    return view('users.index', ['users' => $users]);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15(Request $request)
{
    $column = $request->input('column', 'status');
    $value = $request->input('value', 'active');
    
    $allowedColumns = ['status', 'category', 'type', 'visibility'];
    
    if (!in_array($column, $allowedColumns)) {
        $column = 'status';
    }
    
    // ok: php-laravel-sql-injection
    $results = DB::table('products')->where($column, $value)->get();
    return response()->json($results);
}
// {/fact}
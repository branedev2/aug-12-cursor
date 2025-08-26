<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
// {fact rule=mass-assignment@v1.0 defects=1}

// True Positive Examples - Vulnerable Code

// Example 1: Basic model with empty guarded array
class BadModel1 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    // Other model properties and methods
    protected $table = 'users';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 2: Empty guarded array with fillable also defined (still vulnerable)
class BadModel2 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    // Even with fillable defined, empty guarded is still dangerous
    protected $fillable = ['name', 'email'];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 3: Empty guarded array with array syntax variation
class BadModel3 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = array();
    
    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 4: Empty guarded array in a more complex model
class BadModel4 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $casts = [
        'is_admin' => 'boolean',
        'settings' => 'array',
        'last_login' => 'datetime',
    ];
    
    protected $hidden = ['password', 'remember_token'];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 5: Empty guarded array with timestamps disabled
class BadModel5 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    public $timestamps = false;
    
    protected $primaryKey = 'user_id';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 6: Empty guarded array with custom connection
class BadModel6 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $connection = 'secondary_db';
    
    protected $table = 'customer_data';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 7: Empty guarded array with date serialization
class BadModel7 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $dates = ['created_at', 'updated_at', 'deleted_at', 'last_activity'];
    
    protected $dateFormat = 'Y-m-d H:i:s';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 8: Empty guarded array with accessor and mutator
class BadModel8 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }
    
    public function setPasswordAttribute($value)
    {
        $this->attributes['password'] = bcrypt($value);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 9: Empty guarded array with appends
class BadModel9 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $appends = ['full_name', 'profile_url'];
    
    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 10: Empty guarded array with soft deletes
class BadModel10 extends Model
{
    use \Illuminate\Database\Eloquent\SoftDeletes;
    
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $dates = ['deleted_at'];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 11: Empty guarded array with events
class BadModel11 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected static function boot()
    {
        parent::boot();
        
        static::creating(function ($model) {
            $model->uuid = (string) \Illuminate\Support\Str::uuid();
        });
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 12: Empty guarded array with query scope
class BadModel12 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    public function scopeActive($query)
    {
        return $query->where('active', 1);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 13: Empty guarded array with JSON casting
class BadModel13 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $casts = [
        'preferences' => 'json',
        'metadata' => 'array',
    ];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 14: Empty guarded array with custom primary key and incrementing disabled
class BadModel14 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    protected $primaryKey = 'uuid';
    public $incrementing = false;
    protected $keyType = 'string';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=1}

// Example 15: Empty guarded array with relationship methods
class BadModel15 extends Model
{
    // ruleid: php-laravel-dangerous-model-construction
    protected $guarded = [];
    
    public function author()
    {
        return $this->belongsTo(User::class);
    }
    
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// True Negative Examples - Secure Code

// Example 1: Using guarded with specific attributes protected
class GoodModel1 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'created_at', 'updated_at'];
    
    protected $table = 'users';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 2: Using fillable instead of guarded
class GoodModel2 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['name', 'email', 'password'];
    
    // No guarded property defined
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 3: Guarded with sensitive fields protected
class GoodModel3 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'is_admin', 'role_id', 'created_at', 'updated_at'];
    
    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 4: Comprehensive guarded array
class GoodModel4 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'email_verified_at', 'password', 'remember_token', 'created_at', 'updated_at'];
    
    protected $casts = [
        'is_admin' => 'boolean',
        'settings' => 'array',
        'last_login' => 'datetime',
    ];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 5: Using fillable with timestamps disabled
class GoodModel5 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['name', 'email', 'preferences'];
    
    public $timestamps = false;
    
    protected $primaryKey = 'user_id';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 6: Guarded with custom connection
class GoodModel6 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'created_at', 'updated_at', 'deleted_at', 'secret_key'];
    
    protected $connection = 'secondary_db';
    
    protected $table = 'customer_data';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 7: Using fillable with date serialization
class GoodModel7 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['title', 'content', 'published_at', 'author_id'];
    
    protected $dates = ['created_at', 'updated_at', 'deleted_at', 'published_at'];
    
    protected $dateFormat = 'Y-m-d H:i:s';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 8: Guarded with accessor and mutator
class GoodModel8 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'password', 'api_token', 'created_at', 'updated_at'];
    
    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }
    
    public function setPasswordAttribute($value)
    {
        $this->attributes['password'] = bcrypt($value);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 9: Fillable with appends
class GoodModel9 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['first_name', 'last_name', 'email', 'bio'];
    
    protected $appends = ['full_name', 'profile_url'];
    
    public function getFullNameAttribute()
    {
        return $this->first_name . ' ' . $this->last_name;
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 10: Guarded with soft deletes
class GoodModel10 extends Model
{
    use \Illuminate\Database\Eloquent\SoftDeletes;
    
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'created_at', 'updated_at', 'deleted_at', 'user_id'];
    
    protected $dates = ['deleted_at'];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 11: Fillable with events
class GoodModel11 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['name', 'description', 'status', 'priority'];
    
    protected static function boot()
    {
        parent::boot();
        
        static::creating(function ($model) {
            $model->uuid = (string) \Illuminate\Support\Str::uuid();
        });
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 12: Guarded with query scope
class GoodModel12 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['id', 'role', 'permissions', 'created_at', 'updated_at'];
    
    public function scopeActive($query)
    {
        return $query->where('active', 1);
    }
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 13: Fillable with JSON casting
class GoodModel13 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['name', 'preferences', 'metadata', 'settings'];
    
    protected $casts = [
        'preferences' => 'json',
        'metadata' => 'array',
        'settings' => 'object',
    ];
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 14: Guarded with custom primary key and incrementing disabled
class GoodModel14 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $guarded = ['uuid', 'created_at', 'updated_at', 'secret'];
    
    protected $primaryKey = 'uuid';
    public $incrementing = false;
    protected $keyType = 'string';
}
// {/fact}
// {fact rule=mass-assignment@v1.0 defects=0}

// Example 15: Fillable with relationship methods
class GoodModel15 extends Model
{
    // ok: php-laravel-dangerous-model-construction
    protected $fillable = ['title', 'content', 'published', 'author_id'];
    
    public function author()
    {
        return $this->belongsTo(User::class);
    }
    
    public function comments()
    {
        return $this->hasMany(Comment::class);
    }
}
// {/fact}
import sys
import logging
import os
from contextlib import contextmanager

# TRUE POSITIVES (Vulnerable Code)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1():
    # Setting sys.tracebacklimit globally to a very low value
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = 0
    
    # This will hide all traceback information when an exception occurs
    try:
        result = 1 / 0
    except ZeroDivisionError:
        print("An error occurred")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2():
    # Setting sys.tracebacklimit globally in a function that's called during initialization
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = 1
    
    def process_data(data):
        return data / len(data)
    
    try:
        process_data([])
    except Exception as e:
        logging.error(f"Error processing data: {e}")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3():
    # Setting sys.tracebacklimit conditionally but still globally
    debug_mode = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    if not debug_mode:
        # ruleid: rule-sys-tracebacklimit-set
        sys.tracebacklimit = 2
    
    try:
        with open('nonexistent_file.txt', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print("File not found")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4():
    # Setting sys.tracebacklimit in a try-except block
    try:
        value = int("not_an_integer")
    except ValueError:
        # ruleid: rule-sys-tracebacklimit-set
        sys.tracebacklimit = 3
        print("Invalid value provided")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5():
    # Setting sys.tracebacklimit in a class method
    class ErrorHandler:
        def handle_errors(self):
            # ruleid: rule-sys-tracebacklimit-set
            sys.tracebacklimit = 1
            print("Errors will have limited traceback")
    
    handler = ErrorHandler()
    handler.handle_errors()

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6():
    # Setting sys.tracebacklimit to None (which means no limit, but still modifying the global setting)
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = None
    
    try:
        result = {}['nonexistent_key']
    except KeyError:
        print("Key not found")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7():
    # Setting sys.tracebacklimit through attribute assignment
    # ruleid: rule-sys-tracebacklimit-set
    setattr(sys, 'tracebacklimit', 5)
    
    def complex_calculation():
        return 1/0
    
    try:
        complex_calculation()
    except ZeroDivisionError:
        print("Division by zero")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8():
    # Setting sys.tracebacklimit in a loop
    for i in range(3):
        if i == 2:
            # ruleid: rule-sys-tracebacklimit-set
            sys.tracebacklimit = i
            print(f"Set traceback limit to {i}")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9():
    # Setting sys.tracebacklimit based on a configuration value
    config = {"traceback_limit": 2}
    
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = config["traceback_limit"]
    
    try:
        assert False, "This assertion will fail"
    except AssertionError:
        print("Assertion failed")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10():
    # Setting sys.tracebacklimit in a nested function
    def outer_function():
        def inner_function():
            # ruleid: rule-sys-tracebacklimit-set
            sys.tracebacklimit = 4
            print("Inner function executed")
        
        inner_function()
    
    outer_function()

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11():
    # Setting sys.tracebacklimit with a complex expression
    error_level = 10
    debug_mode = False
    
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = 0 if debug_mode else error_level // 2
    
    try:
        x = [1, 2, 3]
        print(x[10])
    except IndexError:
        print("Index out of range")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12():
    # Setting sys.tracebacklimit in a callback function
    def callback():
        # ruleid: rule-sys-tracebacklimit-set
        sys.tracebacklimit = 1
        print("Callback executed")
    
    callback()

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13():
    # Setting sys.tracebacklimit with an environment variable
    limit = int(os.environ.get('TRACEBACK_LIMIT', '3'))
    
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = limit
    
    try:
        import nonexistent_module
    except ImportError:
        print("Module not found")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14():
    # Setting sys.tracebacklimit in a dictionary comprehension
    limits = {level: level for level in range(5)}
    
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = limits[2]
    
    try:
        result = eval("2 + * 3")
    except SyntaxError:
        print("Syntax error in expression")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15():
    # Setting sys.tracebacklimit with a lambda function
    get_limit = lambda: 2
    
    # ruleid: rule-sys-tracebacklimit-set
    sys.tracebacklimit = get_limit()
    
    try:
        x = None
        print(len(x))
    except TypeError:
        print("Type error occurred")

# TRUE NEGATIVES (Safe Code)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1():
    # Using a local variable instead of modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    traceback_limit = 0
    
    try:
        result = 1 / 0
    except ZeroDivisionError:
        print(f"An error occurred, using local traceback_limit: {traceback_limit}")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2():
    # Using a context manager to temporarily modify sys.tracebacklimit
    @contextmanager
    def temporary_traceback_limit(limit):
        original_limit = getattr(sys, 'tracebacklimit', None)
        try:
            # ok: rule-sys-tracebacklimit-set
            yield limit
        finally:
            if original_limit is None:
                delattr(sys, 'tracebacklimit')
            else:
                sys.tracebacklimit = original_limit
    
    try:
        with temporary_traceback_limit(2):
            result = 1 / 0
    except ZeroDivisionError:
        print("Division by zero error with temporary traceback limit")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3():
    # Using logging configuration instead of modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    logging.basicConfig(
        level=logging.ERROR,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        result = 1 / 0
    except Exception as e:
        logging.exception("An error occurred")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4():
    # Using a custom exception handler instead of modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    def custom_exception_handler(exc_type, exc_value, exc_traceback):
        print(f"Exception type: {exc_type.__name__}")
        print(f"Exception value: {exc_value}")
        # Can control traceback printing here without modifying sys.tracebacklimit
    
    try:
        result = 1 / 0
    except Exception as e:
        custom_exception_handler(type(e), e, e.__traceback__)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5():
    # Reading sys.tracebacklimit without modifying it
    # ok: rule-sys-tracebacklimit-set
    current_limit = getattr(sys, 'tracebacklimit', None)
    print(f"Current traceback limit: {current_limit}")
    
    try:
        result = 1 / 0
    except ZeroDivisionError:
        print("Division by zero error")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6():
    # Using traceback module instead of modifying sys.tracebacklimit
    import traceback
    
    # ok: rule-sys-tracebacklimit-set
    try:
        result = 1 / 0
    except Exception as e:
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=2)
        print(''.join(tb_lines))

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7():
    # Using a class to encapsulate error handling without modifying sys.tracebacklimit
    class ErrorHandler:
        def __init__(self, limit=None):
            self.limit = limit
        
        def handle_error(self, e):
            # ok: rule-sys-tracebacklimit-set
            import traceback
            tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=self.limit)
            print(''.join(tb_lines))
    
    handler = ErrorHandler(limit=2)
    try:
        result = 1 / 0
    except Exception as e:
        handler.handle_error(e)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8():
    # Using exception chaining instead of modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    try:
        try:
            result = 1 / 0
        except ZeroDivisionError as e:
            raise ValueError("Cannot perform calculation") from e
    except ValueError as e:
        print(f"Error: {e}")

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9():
    # Using a function parameter to control traceback depth without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    def process_with_error_handling(data, traceback_limit=None):
        import traceback
        try:
            return data[0] / 0
        except Exception as e:
            tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=traceback_limit)
            print(''.join(tb_lines))
            return None
    
    process_with_error_handling([1, 2, 3], traceback_limit=2)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10():
    # Using a configuration object to store traceback settings without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    class Config:
        def __init__(self):
            self.traceback_limit = 3
    
    config = Config()
    
    try:
        result = 1 / 0
    except Exception as e:
        import traceback
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=config.traceback_limit)
        print(''.join(tb_lines))

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11():
    # Using a dictionary to store error handling configuration without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    error_config = {
        "traceback_limit": 2,
        "log_level": "ERROR"
    }
    
    try:
        result = 1 / 0
    except Exception as e:
        import traceback
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=error_config["traceback_limit"])
        print(''.join(tb_lines))

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12():
    # Using environment variables to configure error handling without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    traceback_limit = int(os.environ.get('TRACEBACK_LIMIT', '5'))
    
    try:
        result = 1 / 0
    except Exception as e:
        import traceback
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=traceback_limit)
        print(''.join(tb_lines))

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13():
    # Using a decorator to handle exceptions without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    def exception_handler(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                import traceback
                tb_lines = traceback.format_exception(type(e), e, e.__traceback__, limit=2)
                print(''.join(tb_lines))
                return None
        return wrapper
    
    @exception_handler
    def divide_by_zero():
        return 1 / 0
    
    result = divide_by_zero()

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14():
    # Using a custom context manager for error handling without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    class ErrorContext:
        def __init__(self, traceback_limit=None):
            self.traceback_limit = traceback_limit
        
        def __enter__(self):
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is not None:
                import traceback
                tb_lines = traceback.format_exception(exc_type, exc_val, exc_tb, limit=self.traceback_limit)
                print(''.join(tb_lines))
            return True  # Suppress exception
    
    with ErrorContext(traceback_limit=2):
        result = 1 / 0

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15():
    # Using a function to format exceptions without modifying sys.tracebacklimit
    # ok: rule-sys-tracebacklimit-set
    def format_exception(e, limit=None):
        import traceback
        return ''.join(traceback.format_exception(type(e), e, e.__traceback__, limit=limit))
    
    try:
        result = 1 / 0
    except Exception as e:
        error_message = format_exception(e, limit=2)
        print(error_message)
# {/fact}
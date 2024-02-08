def error_wrapper(func):
    def error_handler(*args, **kwargs):
        try:
            func(*args, **kwargs)
        
        except Exception as e:
            print("Handled")
            raise RuntimeError(f'Error in {func.__name__}:  + {str(e.args)}')
    return error_handler

@error_wrapper
def test(a,b):
    print(a/b)


test(1,2)
test(2,0)
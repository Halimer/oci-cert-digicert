def error_wrapper(func):
    def error_handler(*args, **kwargs):
        try:
            func(*args, **kwargs)

        except Exception as e:
            print("Handled")
            print("Error in " + func.__name__ + ": " + str(e.args))
            return None
    
    return error_handler


class AcunetixException(Exception):


    def __init__(self, message: str, error_code: int):
        super().__init__(message)
        self.error_code = error_code
    
    def get_error_code(self) -> int:
        return self.error_code
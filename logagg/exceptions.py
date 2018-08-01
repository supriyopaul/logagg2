class BaseException(Exception):
    pass

class InvalidArgument(BaseException):
    def __init__(self, argument):
        self.argument = argument

    def __str__(self):
        return '"{}"'.format(self.argument)

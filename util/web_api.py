class WebAPIException(Exception):
    """Exception raised for failed / unexpected API calls / results

    Attributes:
        url     -- API url
        message -- explanation of the error
    """
    def __init__(self, url=None, data=None, code=None, message=None):
        self.url     = url
        self.data    = data
        self.code    = code
        self.message = message
        super().__init__(self.message)

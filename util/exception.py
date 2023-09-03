class UtilityAPIException(Exception):
    """
    Exception raised for failed / unexpected API calls / results

    Attributes:
        url     -- API endpoint url
        code    -- HTTP status code. Default is 422.
        data    -- JSON response body content
        message -- explanation of the error
    """
    def __init__(self, url=None, code=422, data=None, message='An exception occured.'):
        self.url     = url
        self.code    = code
        self.data    = data
        self.message = message
        super().__init__(self.message)

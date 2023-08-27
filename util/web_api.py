class WebAPIException(Exception):
    """
    Exception raised for failed / unexpected API calls / results

    Attributes:
        url     -- API endpoint url
        code    -- HTTP status code. Default is 422.
        self    -- JSON response body content
        message -- explanation of the error
    """
    def __init__(self, url=None, data=None, code=422, message='An exception occured.'):
        self.url     = url
        self.data    = data
        self.code    = code
        self.message = message
        super().__init__(self.message)

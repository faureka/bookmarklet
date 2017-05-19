WTF_CSRF_ENABLED = True
SECRET_KEY = '6h5kf7psx05+-%kml2h!q)_vk901=*-s49c_qk2zol1p(n!h%z'
SQLALCHEMY_DATABASE_URI = 'postgresql://localhost:5432/faizan'
SQLALCHEMY_COMMIT_ON_TEARDOWN = True
SQLALCHEMY_POOL_SIZE=10
SSL_KEY_PATH='certs/ssl.key'
SSL_CERT_PATH='certs/ssl.cert'
TRAP_HTTP_EXCEPTIONS= True
DEBUG= True
TRAP_BAD_REQUEST_ERRORS = True
PRESERVE_CONTEXT_ON_EXCEPTION = True
COMPRESS_MIMETYPES = ['text/html', 'text/css', 'text/xml', 'application/json', 'application/javascript']
COMPRESS_LEVEL = 6
COMPRESS_MIN_SIZE = 500
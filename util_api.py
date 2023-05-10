from flask import Flask, Response, request, json

import importlib, logging

logging.basicConfig(format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

MODULE_PATH  = 'modules.'

MOD_INVALID  = Response(response = json.dumps({ "result": False, "comment": "Invalid module"} ),
                        status = 404, mimetype = 'application/json')

EP_INVALID   = Response(response = json.dumps({ "result": False, "comment": "Invalid endpoint"} ),
                        status = 404, mimetype = 'application/json')

DATA_INVALID = Response(response = json.dumps({ "result": False, "comment": "Invalid input data" }),
                        status = 403, mimetype = 'application/json')

def handle_bad_request(e):
    return json.dumps({ 'result': False, 'comment': 'bad request' }), 400

app.register_error_handler(400, handle_bad_request)

@app.route('/')
def base():
    return Response(response=json.dumps({"Status": "UP"}),
                    status=200,
                    mimetype='application/json')
  

@app.route('/api/<module>/<endpoint>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_entry( module = None, endpoint = None ):

    try:
        m = importlib.import_module( MODULE_PATH + module)
    except ModuleNotFoundError:
        return MOD_INVALID

    if endpoint not in m.__all__:
        return EP_INVALID

    method = getattr(m, endpoint)
    if not callable(method):
        return EP_INVALID

    data = {}
    if request.data:
        data = request.json
        if not isinstance(data, dict):
            return DATA_INVALID

    return method(method=request.method, data=data, params=request.args.to_dict())

if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
